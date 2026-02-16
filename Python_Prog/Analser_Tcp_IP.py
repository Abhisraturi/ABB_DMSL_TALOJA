import struct
import logging
import sys
import pyodbc
import os
from logging.handlers import TimedRotatingFileHandler
from pymodbus.client import ModbusTcpClient
from time import sleep
from datetime import datetime

# ------------------------------------------------------
# 1. LOGGING SETUP
# ------------------------------------------------------
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR): os.makedirs(LOG_DIR)

logger = logging.getLogger("CEMS_PRO")
logger.setLevel(logging.INFO)
file_handler = TimedRotatingFileHandler(os.path.join(LOG_DIR, "CEMS_Service.log"), when="midnight", backupCount=30)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)
logger.addHandler(logging.StreamHandler(sys.stdout))

# ------------------------------------------------------
# 2. HELPERS
# ------------------------------------------------------
def decode_float(w1, w2, order="ABCD"):
    try:
        b1, b2 = struct.pack(">H", w1), struct.pack(">H", w2)
        order_map = {"ABCD": b1 + b2, "CDAB": b2 + b1}
        return struct.unpack(">f", order_map.get(order, b1 + b2))[0]
    except: return None

def get_rolling_36min_average(conn, table_name):
    """Calculates average of the last 36 mins of LIVE data only."""
    if conn is None: return [0.0]*5
    cursor = None
    try:
        cursor = conn.cursor()
        # Note: This ignores 'PLANT STOP SUBS' or 'SUBSTITUTED' to avoid mathematical drifting
        query = f"""SELECT AVG(CAST(VAL_1 AS FLOAT)), AVG(CAST(VAL_2 AS FLOAT)), 
                           AVG(CAST(VAL_3 AS FLOAT)), AVG(CAST(VAL_4 AS FLOAT)), 
                           AVG(CAST(VAL_5 AS FLOAT)) 
                    FROM [{table_name}] WITH (NOLOCK) 
                    WHERE [DATE] >= DATEADD(minute, -36, GETDATE()) 
                    AND Substitution_Status = 'LIVE'"""
        cursor.execute(query)
        row = cursor.fetchone()
        return [float(v) if v is not None else 0.0 for v in row] if row else [0.0]*5
    except: return [0.0]*5
    finally:
        if cursor: cursor.close()

# ------------------------------------------------------
# 3. CONFIGURATION
# ------------------------------------------------------
SQL_STR = "Driver={ODBC Driver 17 for SQL Server};Server=DESKTOP-F4FK4GN;Database=DATA;UID=Py_User;PWD=Pascal@123;TrustServerCertificate=yes;"
FLOW_IP = "192.168.0.14"
MAINT_IP = "127.0.0.1" 
FLOW_THRESHOLD = 50000

ANALYZERS = [
    {
        "name": "AN1", "ip": "192.168.0.4", "status_ip": "192.168.0.10", "table": "Value",
        "maint_bit": 2,
        "regs": [(0, "ABCD"), (2, "CDAB"), (6, "ABCD")], 
        "cal_map": {1201: "N2O ZERO CAL", 1202: "N2O SPAN CAL", 1203: "NO SPAN CAL", 1204: "O2 SPAN CAL"},
        "lvl_map": {0: "LOW LEVEL CHECK", 1: "MID LEVEL CHECK", 2: "HIGH LEVEL CHECK", 4: "PROBE BACK PURGE"}
    },
    {
        "name": "AN2", "ip": "192.168.0.5", "status_ip": "192.168.0.11", "table": "Value_1",
        "maint_bit": 3,
        "regs": [(0, "ABCD"), (2, "CDAB")], 
        "cal_map": {1203: "AN2 ZERO CAL", 1204: "AN2 N2O SPAN CAL"},
        "lvl_map": {0: "AN2 LOW LVL", 1: "AN2 MID LVL", 2: "AN2 HIGH LVL", 4: "PROBE BACK PURGE"}
    }
]

# ------------------------------------------------------
# 4. MAIN LOOP
# ------------------------------------------------------
conn = None
logger.info("--- CEMS SERVICE ONLINE (SUBSTITUTION ENABLED FOR PLANT STOP) ---")

while True:
    loop_start = datetime.now()
    
    try:
        if conn is None:
            try: conn = pyodbc.connect(SQL_STR, timeout=5)
            except Exception as e: logger.error(f"SQL Connection Failed: {e}")

        # --- A. FLOW METER ---
        flow_val = 0.0
        try:
            with ModbusTcpClient(FLOW_IP, port=502, timeout=2) as flow_cli:
                if flow_cli.connect():
                    r = flow_cli.read_input_registers(address=1, count=2)
                    if not r.isError():
                        flow_val = decode_float(r.registers[0], r.registers[1], "ABCD") or 0.0
        except: pass 
        
        is_plant_stop = flow_val < FLOW_THRESHOLD

        # --- B. ANALYZER PROCESSING ---
        for p in ANALYZERS:
            curr_an_mode, curr_lvl_mode, sub_tag, purge_status = "ANALYZER IDLE", "LEVEL IDLE", "LIVE", "OFF"
            is_cal_active, is_maint_active, raw_data = False, False, None
            
            # 1. READ LOCAL MAINTENANCE
            try:
                with ModbusTcpClient(MAINT_IP, port=502, timeout=2) as maint_cli:
                    if maint_cli.connect():
                        m_res = maint_cli.read_discrete_inputs(address=p["maint_bit"], count=1)
                        if not m_res.isError() and m_res.bits[0]:
                            is_maint_active = True
                            curr_an_mode = "ANALYZER MAINTENANCE"
            except: pass

            # 2. READ PLC (Purge Status)
            try:
                with ModbusTcpClient(p["status_ip"], port=502, timeout=2) as plc_cli:
                    if plc_cli.connect():
                        for bit, name in p["lvl_map"].items():
                            rb = plc_cli.read_discrete_inputs(address=bit, count=1)
                            if not rb.isError() and rb.bits[0]:
                                curr_lvl_mode = name
                                if name == "PROBE BACK PURGE": purge_status = "ON"
                                break
                    else: curr_lvl_mode = "PLC OFFLINE"
            except: curr_lvl_mode = "PLC OFFLINE"

            # 3. READ ANALYZER (Data & Calibration)
            try:
                with ModbusTcpClient(p["ip"], port=502, timeout=2) as an_cli:
                    if an_cli.connect():
                        for bit, name in p["cal_map"].items():
                            rb = an_cli.read_discrete_inputs(address=bit, count=1)
                            if not rb.isError() and rb.bits[0]:
                                curr_an_mode, is_cal_active = name, True
                                break 

                        max_addr = max(a for a, f in p["regs"]) + 2
                        res = an_cli.read_input_registers(address=0, count=max_addr)
                        if not res.isError():
                            raw_data = [decode_float(res.registers[a], res.registers[a+1], f) for a, f in p["regs"]]
                    else:
                        if not is_maint_active: curr_an_mode = "ANALYZER OFFLINE"
            except: 
                if not is_maint_active: curr_an_mode = "ANALYZER OFFLINE"

            # 4. UPDATED DECISION ENGINE
            # Logic: If Plant is stopped OR Analyzer is unhealthy, trigger substitution
            is_unhealthy = (raw_data is None) or is_cal_active or is_maint_active or (curr_lvl_mode not in ["LEVEL IDLE", "PLC OFFLINE"])
            
            if is_plant_stop or is_unhealthy:
                # Use rolling average instead of forcing zero
                final_vals = get_rolling_36min_average(conn, p["table"])
                
                if is_plant_stop:
                    sub_tag = "SUBSTITUTED"
                else:
                    sub_tag = "SUBSTITUTED"
            else:
                # Normal live operation
                final_vals = ([v if v is not None else 0.0 for v in raw_data] + [0.0]*5)[:5]
                sub_tag = "LIVE"

            # 5. SQL INSERT
            if conn:
                try:
                    with conn.cursor() as cursor:
                        sql = f"""INSERT INTO [{p['table']}] 
                                  ([DATE], VAL_1, VAL_2, VAL_3, VAL_4, VAL_5, Flow, 
                                  Analyzer_Mode, Level_Mode, IsCalibration, 
                                  Plant_Status, Substitution_Status, Purge_Status) 
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
                        
                        cursor.execute(sql, (
                            datetime.now(), *final_vals, flow_val, 
                            curr_an_mode, curr_lvl_mode, 
                            int(is_cal_active or is_maint_active),
                            ("STOP" if is_plant_stop else "RUNNING"), 
                            sub_tag, purge_status
                        ))
                        conn.commit()
                        logger.info(f"{p['name']} | Status: {sub_tag} | Flow: {flow_val:.1f}")
                        
                except Exception as sql_e:
                    logger.error(f"SQL Error: {sql_e}")
                    if "10054" in str(sql_e): conn = None

    except Exception as ge:
        logger.critical(f"Global Loop Error: {ge}")

    elapsed = (datetime.now() - loop_start).total_seconds()
    sleep(max(1, 60 - elapsed))