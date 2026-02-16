#!/usr/bin/env python3

import os
import sys
import time
import struct
import threading
import logging
from datetime import datetime
import pyodbc
from pymodbus.client import ModbusTcpClient
from logging.handlers import RotatingFileHandler

# ============================================================
# --- LOGGING SETUP ---
# ============================================================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_path = os.path.join(LOG_DIR, "AN_2_VAL.log")

handler = RotatingFileHandler(log_path, maxBytes=10_000_000, backupCount=10, encoding="utf-8")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
    handlers=[handler, logging.StreamHandler(sys.stdout)],
)
print = logging.info

# ============================================================
# --- CONFIGURATION (REVERTED TO ORIGINAL ADDRESSES) ---
# ============================================================
STATUS_DEVICE_IP = "192.168.0.11"
VALUE_DEVICE_IP = "192.168.0.5"
ACTUAL_VALUE_IP = "127.0.0.1"

# Using your original 0, 1, 2 mapping
STATUS_REGISTERS = [0, 1, 2] 
LEVEL_NAMES = {0: "Low Level", 1: "Mid Level", 2: "High Level"}

VALUE_REGISTER = 0                # Sensor Input
ACTUAL_VALUE_REGISTER = 121       # Reference for Mid Level
HIGH_LEVEL_ACTUAL_REGISTER = 129  # Reference for High Level
LOW_LEVEL_ACTUAL_REGISTER = None   # Forced to 0.0 for Zero Calibration

# SQL Config
SERVER_NAME = "DESKTOP-F4FK4GN"
DATABASE_NAME = "DATA"
USERNAME = "a"
PASSWORD = "1234"
TABLE_NAME = "LevelCapture_1"

# ============================================================
# --- HELPERS ---
# ============================================================

def decode_float(w1, w2, order="ABCD"):
    """Decodes two 16-bit registers into a 32-bit float."""
    try:
        b1, b2 = struct.pack(">H", w1), struct.pack(">H", w2)
        order_map = {
            "ABCD": b1 + b2, 
            "CDAB": b2 + b1, 
            "BADC": b1[::-1] + b2[::-1], 
            "DCBA": b2[::-1] + b1[::-1]
        }
        return struct.unpack(">f", order_map[order])[0]
    except Exception:
        return None

def connect_sql():
    """Establishes connection to SQL Server."""
    try:
        conn_str = (
            f"Driver={{ODBC Driver 17 for SQL Server}};"
            f"Server={SERVER_NAME};Database={DATABASE_NAME};"
            f"UID={USERNAME};PWD={PASSWORD};"
        )
        return pyodbc.connect(conn_str, timeout=5)
    except Exception as e:
        logging.error(f"[DB] Connection failed: {e}")
        return None

def insert_value(cursor, timestamp, level_name, value_type, value):
    """Executes SQL Insert."""
    try:
        cursor.execute(
            f"INSERT INTO {TABLE_NAME} ([Timestamp],[LevelName],[ValueType],[Value]) VALUES (?,?,?,?)",
            timestamp, level_name, value_type, value,
        )
    except Exception as e:
        logging.error(f"[DB] Insert error: {e}")

# ============================================================
# --- CAPTURE THREAD LOGIC ---
# ============================================================

def capture_and_insert(level_name, actual_register):
    """Wait, Sample 3 times, Average, Compare, and Save."""
    logging.info(f"[{level_name}] Capture thread started.")
    delays = [180, 60, 60]
    values = []

    conn = connect_sql()
    if conn is None: return
    
    try:
        cursor = conn.cursor()
        
        # --- PHASE 1: Collect 3 Sensor Readings ---
        with ModbusTcpClient(host=VALUE_DEVICE_IP, port=502) as value_client:
            for i, delay in enumerate(delays, 1):
                time.sleep(delay)
                
                val = None
                for attempt in range(3):
                    try:
                        if not value_client.connect(): 
                            time.sleep(1)
                            continue
                        res = value_client.read_input_registers(address=VALUE_REGISTER, count=2)
                        if not res.isError():
                            val = decode_float(res.registers[0], res.registers[1], "ABCD")
                            break
                    except Exception as e:
                        logging.warning(f"[{level_name}] Read retry {attempt+1}: {e}")
                        value_client.close()
                
                if val is not None:
                    logging.info(f"[{level_name}] Sample {i}: {val:.4f}")
                    insert_value(cursor, datetime.now(), level_name, f"Val {i}", val)
                    values.append(val)

        # --- PHASE 2: Calculation & Comparison ---
        if values:
            avg_val = sum(values) / len(values)
            insert_value(cursor, datetime.now(), level_name, "Avg", avg_val)

            # Determine Reference (Actual) Value
            actual_val = 0.0 # Default for Zero Calibration
            if actual_register is not None:
                with ModbusTcpClient(host=ACTUAL_VALUE_IP, port=502) as actual_client:
                    try:
                        actual_client.connect()
                        res = actual_client.read_holding_registers(address=actual_register, count=2)
                        if not res.isError():
                            actual_val = decode_float(res.registers[0], res.registers[1], "CDAB")
                    except Exception as e:
                        logging.error(f"[{level_name}] Reference read failed: {e}")
                    finally:
                        actual_client.close()

            error = avg_val - actual_val
            p_error = abs((error / actual_val) * 100) if actual_val != 0 else 0.0

            # Log results
            t = datetime.now()
            insert_value(cursor, t, level_name, "Actual", actual_val)
            insert_value(cursor, t, level_name, "Error", error)
            insert_value(cursor, t, level_name, "% Error", p_error)
            
            conn.commit()
            logging.info(f"[{level_name}] Success. Avg: {avg_val:.4f}, Actual: {actual_val:.4f}")
        else:
            logging.error(f"[{level_name}] No readings captured.")

    except Exception as e:
        logging.error(f"[{level_name}] Thread error: {e}")
    finally:
        conn.close()

# ============================================================
# --- MAIN MONITORING LOOP ---
# ============================================================

def main():
    logging.info("Resilient Monitoring System Active")
    status_flags = {reg: False for reg in STATUS_REGISTERS}
    
    # Persistent status client
    status_client = ModbusTcpClient(host=STATUS_DEVICE_IP, port=502)

    while True:
        try:
            # Reconnect if 10054 error occurred previously
            if not status_client.connected:
                if not status_client.connect():
                    logging.error("PLC at .10 Offline. Retrying in 5s...")
                    time.sleep(5)
                    continue

            for reg in STATUS_REGISTERS:
                try:
                    # Read discrete inputs (0, 1, or 2)
                    res = status_client.read_discrete_inputs(address=reg, count=1)
                    if res.isError(): continue
                    
                    status = res.bits[0]

                    # Triggered (ON)
                    if status and not status_flags[reg]:
                        level_name = LEVEL_NAMES.get(reg)
                        logging.info(f"[{level_name}] Triggered.")

                        if level_name == "High Level": addr = HIGH_LEVEL_ACTUAL_REGISTER
                        elif level_name == "Low Level": addr = LOW_LEVEL_ACTUAL_REGISTER
                        else: addr = ACTUAL_VALUE_REGISTER

                        t = threading.Thread(
                            target=capture_and_insert, 
                            args=(level_name, addr),
                            daemon=True, name=level_name
                        )
                        t.start()
                        status_flags[reg] = True

                    # Reset (OFF)
                    elif not status and status_flags[reg]:
                        status_flags[reg] = False

                except Exception as e:
                    logging.warning(f"Connection reset at register {reg}: {e}")
                    status_client.close() # Reset socket to clear 10054
                    break 

        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Main Loop error: {e}")
            time.sleep(5)

        time.sleep(1.0)

if __name__ == "__main__":
    main()