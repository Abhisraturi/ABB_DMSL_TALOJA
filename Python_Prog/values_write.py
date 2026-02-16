import time
import struct
import logging
import sys
import os
import traceback
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
import pyodbc
from pyModbusTCP.client import ModbusClient

# --- CONFIGURATION ---
SQL_CONN_STR = "Driver={ODBC Driver 17 for SQL Server};Server=DESKTOP-F4FK4GN;Database=DATA;UID=Py_User;PWD=Pascal@123;"
MODBUS_IP = '127.0.0.1'
MODBUS_PORT = 502
UNIT_ID = 1
POLL_INTERVAL = 2
RESTART_DELAY = 5  # Cooldown before restarting after a crash

# --- LOGGING PATH SETUP ---
LOG_DIR = Path(r"C:\PROG\logs")
LOG_FILE = LOG_DIR / "plc_sync_service.log"

try:
    # Ensure the directory exists for NSSM
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Fallback to local directory if C:\PROG is restricted
    LOG_FILE = Path("plc_sync_service_fallback.log")

# --- INDUSTRIAL LOGGING (7-DAY RETENTION) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        # Rotates every day (midnight), keeps 7 days of history
        TimedRotatingFileHandler(
            str(LOG_FILE), 
            when="D", 
            interval=1, 
            backupCount=7,
            encoding='utf-8'
        ),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- HELPERS ---
def registers_to_float(regs):
    """Converts two 16-bit registers to 32-bit float (Big Endian)."""
    try:
        if not regs or len(regs) != 2: return None
        return struct.unpack('>f', struct.pack('>HH', regs[0], regs[1]))[0]
    except Exception: return None

def float_to_registers(value):
    """Converts python float to two 16-bit registers."""
    try:
        return list(struct.unpack('>HH', struct.pack('>f', float(value))))
    except Exception: return [0, 0]

# --- MAIN ENGINE ---
class SyncEngine:
    def __init__(self):
        self.db_conn = None
        self.modbus_client = ModbusClient(host=MODBUS_IP, port=MODBUS_PORT, unit_id=UNIT_ID, auto_open=True)
        self.local_cache = {}

    def connect_and_init(self):
        """Setup connections and perform initial DB -> PLC sync."""
        logger.info("Connecting to SQL Server...")
        self.db_conn = pyodbc.connect(SQL_CONN_STR, timeout=5)
        cursor = self.db_conn.cursor()
        
        logger.info("Reading map and performing initial sync to PLC...")
        cursor.execute("SELECT Value, ModbusAddress FROM AnalyzerModbusMap")
        rows = cursor.fetchall()
        
        for row in rows:
            if row.Value is not None:
                addr = row.ModbusAddress
                val = float(row.Value)
                regs = float_to_registers(val)
                if self.modbus_client.write_multiple_registers(addr, regs):
                    self.local_cache[addr] = val
                else:
                    logger.warning(f"Initial Write Failed at Addr {addr}")
        
        logger.info(f"Sync complete. Monitoring {len(self.local_cache)} addresses.")

    def monitor_loop(self):
        """Primary polling loop: PLC -> Database."""
        cursor = self.db_conn.cursor()
        while True:
            for addr, last_val in list(self.local_cache.items()):
                # Read 2 registers (32-bit float)
                regs = self.modbus_client.read_holding_registers(addr, 2)
                
                if regs:
                    curr_val = registers_to_float(regs)
                    # Use a small delta for float comparison to avoid jitter
                    if curr_val is not None and abs(curr_val - last_val) > 0.001:
                        logger.info(f"Change: Addr {addr} | {last_val:.2f} -> {curr_val:.2f}")
                        
                        cursor.execute(
                            "UPDATE AnalyzerModbusMap SET Value=? WHERE ModbusAddress=?", 
                            (curr_val, addr)
                        )
                        self.db_conn.commit()
                        self.local_cache[addr] = curr_val
                else:
                    # Occasional timeouts are normal in industrial WiFi/Serial, log as warning
                    logger.warning(f"Modbus Read Timeout at address {addr}")
            
            time.sleep(POLL_INTERVAL)

# --- GLOBAL RESTART WRAPPER ---
def main():
    logger.info("=== STARTING PLC SYNC SERVICE WRAPPER ===")
    
    while True:
        engine = None
        try:
            engine = SyncEngine()
            engine.connect_and_init()
            engine.monitor_loop()
        except KeyboardInterrupt:
            logger.info("Service manually stopped (KeyboardInterrupt).")
            break
        except Exception:
            # CAPTURE EVERYTHING: SQL loss, PLC loss, Code bugs
            error_trace = traceback.format_exc()
            logger.error(f"CRITICAL SYSTEM ERROR:\n{error_trace}")
            
            # Clean up connections
            if engine and engine.db_conn:
                try: engine.db_conn.close()
                except: pass
            
            logger.info(f"Initiating automatic restart in {RESTART_DELAY} seconds...")
            time.sleep(RESTART_DELAY)

if __name__ == "__main__":
    main()