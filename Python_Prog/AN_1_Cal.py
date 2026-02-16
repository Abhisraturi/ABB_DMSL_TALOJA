#!/usr/bin/env python3

import threading
import queue
import time
import struct
import logging
import os
import sys
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pymodbus.client import ModbusTcpClient
import pyodbc

# ============================================================
# --- LOGGING SETUP ---
# ============================================================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, "AN_1_Cal.log")
handler = RotatingFileHandler(log_path, maxBytes=10_000_000, backupCount=5)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[handler, logging.StreamHandler(sys.stdout)]
)

# ============================================================
# --- CONFIGURATION ---
# ============================================================
PLC_IP = "192.168.0.4"
RANGE_IP = "127.0.0.1"
SQL_STR = "Driver={ODBC Driver 17 for SQL Server};Server=DESKTOP-F4FK4GN;Database=DATA;UID=Py_User;PWD=Pascal@123;"
TABLE_NAME = "CAL"

INPUT_STATUS_REGS = {
    1201: {"name": "N₂O ZERO", "delay": 120, "max_duration_m": 10, "capture": ["N₂O"]},
    1202: {"name": "N₂O SPAN",  "delay": 60,  "max_duration_m": 5,  "capture": ["N₂O"]}
}

INPUT_REG_MAP = {
    "N₂O": (0, "ABCD", 124, 100, 102, 100),
}

def decode_float(w1, w2, order="ABCD"):
    try:
        b1, b2 = struct.pack(">H", w1), struct.pack(">H", w2)
        order_map = {"ABCD": b1+b2, "CDAB": b2+b1}
        return struct.unpack(">f", order_map.get(order, b1+b2))[0]
    except: return None

# ============================================================
# --- CAPTURE ENGINE ---
# ============================================================
def run_capture_sequence(reg_addr, out_q, stop_event):
    info = INPUT_STATUS_REGS[reg_addr]
    cal_name = info['name']
    tags = info['capture']
    
    logging.info(f"STATUS: {cal_name} initiated. Waiting {info['delay']}s for stabilization.")
    
    for _ in range(info['delay']):
        if stop_event.is_set(): return
        time.sleep(1)
    
    logging.info(f"STATUS: {cal_name} stabilization complete. Starting data capture.")
    max_end_time = datetime.now() + timedelta(minutes=info['max_duration_m'])

    while not stop_event.is_set() and datetime.now() < max_end_time:
        loop_start = time.time()
        
        with ModbusTcpClient(PLC_IP, port=502, timeout=5) as plc:
            if plc.connect():
                st = plc.read_discrete_inputs(address=reg_addr, count=1)
                if st.isError() or not st.bits[0]:
                    logging.info(f"STATUS: {cal_name} trigger lost. Sequence ended.")
                    break
                
                for tag in tags:
                    addr, fmt, exp_reg, min_reg, max_reg, factor = INPUT_REG_MAP[tag]
                    res = plc.read_input_registers(address=addr, count=2)
                    
                    if not res.isError():
                        val = decode_float(res.registers[0], res.registers[1], fmt)
                        
                        if val is not None:
                            # --- Logic Branch: Zero vs Span ---
                            # Using 'in' for robustness against trailing spaces in Modbus strings
                            if "ZERO" in cal_name:
                                expected, min_v, max_v = 0.0, -40.0, 40.0
                            else:
                                # Only pull from Range PLC if this is NOT a Zero calibration
                                with ModbusTcpClient(RANGE_IP, port=502, timeout=5) as r_cli:
                                    if r_cli.connect():
                                        e = r_cli.read_holding_registers(address=exp_reg-1, count=2)
                                        mi = r_cli.read_holding_registers(address=min_reg-1, count=2)
                                        ma = r_cli.read_holding_registers(address=max_reg-1, count=2)
                                        
                                        expected = decode_float(e.registers[0], e.registers[1], "CDAB") if not e.isError() else None
                                        min_v = decode_float(mi.registers[0], mi.registers[1], "CDAB") if not mi.isError() else None
                                        max_v = decode_float(ma.registers[0], ma.registers[1], "CDAB") if not ma.isError() else None
                                    else:
                                        expected = None

                            # --- Data Processing and Storage ---
                            if expected is not None and min_v is not None and max_v is not None:
                                err = val - expected
                                acc = (abs(err)/expected * factor) if expected != 0 else (abs(val)*factor)
                                stat = "CAL OK" if (min_v <= val <= max_v) else "OUT OF CONTROL"
                                
                                out_q.put({
                                    "DATE": datetime.now(), "CAL_NAME": cal_name, "NAME": tag, 
                                    "VAL": val, "EXPECTED": expected, "ERROR": err, 
                                    "ACCURACY": acc, "STATUS": stat
                                })
                                
                                logging.info(f"DATA: {cal_name.strip()} | Val: {val:.3f} | Ref: {expected} | Limits: [{min_v:.2f} to {max_v:.2f}] | Status: {stat}")
                            else:
                                logging.warning(f"ERROR: {cal_name} Reference values unavailable.")
                    else:
                        logging.warning(f"ERROR: {cal_name} Modbus read failure at address {addr}")
            else:
                logging.warning(f"ERROR: {cal_name} could not connect to {PLC_IP}")

        # Maintain 10-second polling interval
        time.sleep(max(0, 10 - (time.time() - loop_start)))

# ============================================================
# --- SQL WRITER ---
# ============================================================
def sql_worker(out_q, stop_event):
    conn = None
    while not stop_event.is_set():
        try:
            if conn is None:
                conn = pyodbc.connect(SQL_STR, timeout=10)
                logging.info("SQL: Database connection established.")

            data = out_q.get(timeout=2)
            with conn.cursor() as cur:
                query = f"INSERT INTO {TABLE_NAME} (DATE, CAL_NAME, NAME, VAL, EXPECTED, ERROR, ACCURACY, STATUS) VALUES (?,?,?,?,?,?,?,?)"
                cur.execute(query, data["DATE"], data["CAL_NAME"], data["NAME"], data["VAL"], data["EXPECTED"], data["ERROR"], data["ACCURACY"], data["STATUS"])
                conn.commit()
                logging.info(f"SQL: Saved record for {data['CAL_NAME'].strip()}")

        except queue.Empty: continue
        except Exception as e:
            logging.error(f"SQL_ERROR: {str(e)}")
            conn = None
            time.sleep(5)

# ============================================================
# --- MAIN MONITOR ---
# ============================================================
def main():
    stop_event = threading.Event()
    out_q = queue.Queue()
    threading.Thread(target=sql_worker, args=(out_q, stop_event), daemon=True, name="SQL").start()
    last_status = {reg: False for reg in INPUT_STATUS_REGS}

    logging.info("System started. Monitoring PLC trigger registers.")

    while True:
        with ModbusTcpClient(PLC_IP, port=502, timeout=5) as client:
            try:
                if client.connect():
                    for reg in INPUT_STATUS_REGS:
                        res = client.read_discrete_inputs(address=reg, count=1)
                        curr = res.bits[0] if not res.isError() else False
                        
                        # Trigger on Rising Edge
                        if curr and not last_status[reg]:
                            threading.Thread(target=run_capture_sequence, args=(reg, out_q, stop_event), daemon=True, name=f"Thread_{reg}").start()
                        last_status[reg] = curr
                else:
                    logging.error(f"FAULT: Could not connect to Master PLC at {PLC_IP}")
            except Exception as e: 
                logging.error(f"FAULT: {str(e)}")
        
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("System shutdown requested by user.")
        sys.exit(0)