#!/usr/bin/env python3
"""
Combined Gas Analyzer Monitoring System - Multi-Threaded Version
Integrates: Data Logging + Calibration Detection + Level Mode Tracking
Maps to: [Value] table with VAL_1-5, Flow, Analyzer_Mode, Level_Mode, IsCalibration, Plant_Status

Architecture:
- Thread 1: Analyzer 1 reader (VAL_1, VAL_2, VAL_3)
- Thread 2: Analyzer 2 reader (VAL_4, VAL_5)
- Thread 3: Flow meter reader
- Thread 4: Status monitor (calibration & level mode)
- Thread 5: Validation & database writer
"""

import struct
import logging
import threading
import queue
import time
from logging.handlers import TimedRotatingFileHandler
from pymodbus.client import ModbusTcpClient
from datetime import datetime
import pyodbc
import os
from collections import defaultdict

# ============================================================
# LOGGING SETUP
# ============================================================
def setup_logger():
    logger = logging.getLogger("Combined_Analyzer")
    logger.setLevel(logging.INFO)

    # File handler
    handler = TimedRotatingFileHandler(
        "Combined_Analyzer.log",
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8"
    )
    handler.setLevel(logging.INFO)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    console.setFormatter(formatter)

    logger.handlers = [handler, console]
    return logger

logger = setup_logger()

# ============================================================
# CONFIGURATION
# ============================================================
# SQL Server Configuration
SQL_SERVER = os.getenv("SQL_SERVER", "DESKTOP-F4FK4GN")
SQL_DATABASE = os.getenv("SQL_DATABASE", "DATA")
SQL_UID = os.getenv("SQL_UID", "Py_User")
SQL_PWD = os.getenv("SQL_PWD", "Pascal@123")

# PLC IP Addresses
ANALYZER_PLC_IP = "192.168.0.4"      # Main analyzer values (VAL_1, VAL_2, VAL_3)
ANALYZER_PLC_IP_2 = "192.168.0.5"    # Additional analyzer values (VAL_4, VAL_5)
FLOW_PLC_IP = "192.168.0.14"         # Flow meter
STATUS_PLC_IP = "192.168.0.10"       # Status bits for modes
RANGE_PLC_IP = "127.0.0.1"           # For calibration range checking

# Modbus Register Maps
# Format: (register_address, byte_order)
ANALYZER_1_REGS = [
    (0, "ABCD"),   # VAL_1: N2O
    (2, "CDAB"),   # VAL_2: NO
    (6, "ABCD"),   # VAL_3: O2
]

ANALYZER_2_REGS = [
    (0, "ABCD"),   # VAL_4
    (2, "CDAB"),   # VAL_5
]

FLOW_REG = (1, "ABCD")

# Status Discrete Input Registers
CALIBRATION_STATUS_REGS = {
    1201: "ZERO N20",
    1202: "SPAN N2O",
    1203: "SPAN NO",
    1204: "SPAN O2",
}

LEVEL_STATUS_REGS = {
    0: "LOW",
    1: "MID",
    2: "HIGH",
}

# Minimum limit registers for validation (holding registers)
MIN_LIMIT_MAP = {
    "VAL_1": {"ip": "127.0.0.1", "reg": 99, "order": "CDAB"},
    "VAL_2": {"ip": "127.0.0.1", "reg": 103, "order": "CDAB"},
    "VAL_3": {"ip": "127.0.0.1", "reg": 107, "order": "CDAB"},
    "VAL_4": {"ip": "127.0.0.1", "reg": 111, "order": "CDAB"},
    "VAL_5": {"ip": "127.0.0.1", "reg": 117, "order": "CDAB"},
}

# Thresholds
FLOW_THRESHOLD = 100.0  # Plant running if flow >= 100
SCAN_INTERVAL = 60      # Main loop interval (seconds)

# ============================================================
# MODBUS UTILITIES
# ============================================================
def decode_float(w1, w2, order="ABCD"):
    """Decode two Modbus registers into a float."""
    b1 = struct.pack('>H', w1)
    b2 = struct.pack('>H', w2)
    
    order_map = {
        "ABCD": b1 + b2,
        "CDAB": b2 + b1,
        "BADC": b1[::-1] + b2[::-1],
        "DCBA": b2[::-1] + b1[::-1]
    }
    
    if order not in order_map:
        raise ValueError(f"Invalid byte order: {order}")
    
    return struct.unpack('>f', order_map[order])[0]


def read_input_registers(ip, reg_map, timeout=3):
    """
    Read input registers from PLC.
    reg_map: list of (address, byte_order) tuples
    Returns: list of float values or None on error
    """
    client = ModbusTcpClient(ip, port=502, timeout=timeout)
    
    if not client.connect():
        logger.warning(f"Failed to connect to {ip}")
        return None
    
    try:
        # Calculate max register needed
        max_reg = max(addr for addr, _ in reg_map) + 2
        result = client.read_input_registers(0, max_reg)
        
        if result.isError():
            logger.warning(f"Error reading input registers from {ip}")
            return None
        
        values = []
        for addr, order in reg_map:
            val = decode_float(result.registers[addr], result.registers[addr + 1], order)
            values.append(val)
        
        return values
    
    except Exception as e:
        logger.error(f"Exception reading from {ip}: {e}")
        return None
    
    finally:
        client.close()


def read_holding_register_float(ip, reg, order="CDAB", timeout=3):
    """Read a float from holding registers."""
    client = ModbusTcpClient(ip, port=502, timeout=timeout)
    
    try:
        if not client.connect():
            return None
        
        result = client.read_holding_registers(reg, 2)
        if result.isError():
            return None
        
        return decode_float(result.registers[0], result.registers[1], order)
    
    except Exception as e:
        logger.error(f"Error reading holding register {reg} from {ip}: {e}")
        return None
    
    finally:
        client.close()


def read_discrete_input(client, address):
    """Read a discrete input bit."""
    try:
        result = client.read_discrete_inputs(address, 1)
        if result.isError():
            return None
        return result.bits[0]
    except Exception as e:
        logger.error(f"Error reading discrete input {address}: {e}")
        return None

# ============================================================
# SQL DATABASE
# ============================================================
def connect_sql(retries=5, delay=5):
    """Connect to SQL Server with retry logic."""
    conn_str = (
        f"Driver={{ODBC Driver 17 for SQL Server}};"
        f"Server={SQL_SERVER};"
        f"Database={SQL_DATABASE};"
        f"UID={SQL_UID};"
        f"PWD={SQL_PWD};"
        f"TrustServerCertificate=yes;"
    )
    
    for attempt in range(retries):
        try:
            conn = pyodbc.connect(conn_str, timeout=10)
            logger.info(f"✅ SQL Server connected successfully")
            return conn
        except Exception as e:
            logger.warning(f"SQL connection attempt {attempt + 1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    
    logger.error("❌ Failed to connect to SQL Server after all retries")
    return None


def insert_value_record(conn, val1, val2, val3, val4, val5, flow, 
                       analyzer_mode, level_mode, is_calibration, plant_status):
    """
    Insert a record into the [Value] table.
    Schema:
    - DATE: datetime
    - VAL_1, VAL_2, VAL_3: Main analyzer values (N2O, NO, O2)
    - VAL_4, VAL_5: Additional values
    - Flow: Flow meter value
    - Analyzer_Mode: "IDLE" | "ZERO N20" | "SPAN N2O" | "SPAN NO" | "SPAN O2" | "OFFLINE" | "INVALID"
    - Level_Mode: "LOW" | "MID" | "HIGH" | "IDLE"
    - IsCalibration: 1 if in calibration, 0 otherwise
    - Plant_Status: "RUNNING" | "STOPPED"
    """
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO [DATA].[dbo].[Value]
            ([DATE], [VAL_1], [VAL_2], [VAL_3], [VAL_4], [VAL_5], 
             [Flow], [Analyzer_Mode], [Level_Mode], [IsCalibration], [Plant_Status])
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            datetime.now(),
            val1, val2, val3, val4, val5,
            flow,
            analyzer_mode,
            level_mode,
            is_calibration,
            plant_status
        )
        conn.commit()
        cursor.close()
        logger.info(f"✅ Record inserted: Analyzer={analyzer_mode}, Level={level_mode}, Flow={flow:.2f}")
        return True
    
    except Exception as e:
        logger.error(f"❌ SQL insert failed: {e}")
        return False

# ============================================================
# STATUS DETECTION
# ============================================================
class StatusMonitor:
    """Monitor calibration and level status from status PLC."""
    
    def __init__(self, status_ip):
        self.status_ip = status_ip
        self.client = None
    
    def connect(self):
        """Connect to status PLC."""
        self.client = ModbusTcpClient(self.status_ip, port=502, timeout=3)
        return self.client.connect()
    
    def disconnect(self):
        """Disconnect from status PLC."""
        if self.client:
            self.client.close()
            self.client = None
    
    def get_calibration_mode(self):
        """
        Check calibration status bits.
        Returns: calibration type string or "IDLE"
        """
        if not self.client or not self.client.connected:
            if not self.connect():
                return "IDLE"
        
        for reg, mode_name in CALIBRATION_STATUS_REGS.items():
            status = read_discrete_input(self.client, reg)
            if status:
                return mode_name
        
        return "IDLE"
    
    def get_level_mode(self):
        """
        Check level status bits.
        Returns: level mode string or "IDLE"
        """
        if not self.client or not self.client.connected:
            if not self.connect():
                return "IDLE"
        
        for reg, level_name in LEVEL_STATUS_REGS.items():
            status = read_discrete_input(self.client, reg)
            if status:
                return level_name
        
        return "IDLE"

# ============================================================
# VALIDATION
# ============================================================
def validate_values(values):
    """
    Validate analyzer values against minimum thresholds.
    Returns: True if all valid, False if any value below minimum
    """
    value_names = ["VAL_1", "VAL_2", "VAL_3", "VAL_4", "VAL_5"]
    
    for i, val in enumerate(values):
        if val is None:
            continue
        
        val_name = value_names[i]
        if val_name not in MIN_LIMIT_MAP:
            continue
        
        cfg = MIN_LIMIT_MAP[val_name]
        min_val = read_holding_register_float(cfg["ip"], cfg["reg"], cfg["order"])
        
        if min_val is not None and val < min_val:
            logger.warning(f"⚠️ {val_name}={val:.3f} is below minimum {min_val:.3f}")
            return False
    
    return True

# ============================================================
# THREAD-SAFE DATA STORAGE
# ============================================================
class SharedData:
    """Thread-safe storage for analyzer data."""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {
            'analyzer_1': {'values': [0.0, 0.0, 0.0], 'timestamp': None, 'online': False},
            'analyzer_2': {'values': [0.0, 0.0], 'timestamp': None, 'online': False},
            'flow': {'value': 0.0, 'timestamp': None, 'online': False},
            'calibration_mode': 'IDLE',
            'level_mode': 'IDLE',
            'last_good_values': [0.0, 0.0, 0.0, 0.0, 0.0]
        }
    
    def update_analyzer_1(self, values, online=True):
        """Update analyzer 1 values (VAL_1, VAL_2, VAL_3)."""
        with self.lock:
            self.data['analyzer_1']['values'] = values
            self.data['analyzer_1']['timestamp'] = datetime.now()
            self.data['analyzer_1']['online'] = online
    
    def update_analyzer_2(self, values, online=True):
        """Update analyzer 2 values (VAL_4, VAL_5)."""
        with self.lock:
            self.data['analyzer_2']['values'] = values
            self.data['analyzer_2']['timestamp'] = datetime.now()
            self.data['analyzer_2']['online'] = online
    
    def update_flow(self, value, online=True):
        """Update flow value."""
        with self.lock:
            self.data['flow']['value'] = value
            self.data['flow']['timestamp'] = datetime.now()
            self.data['flow']['online'] = online
    
    def update_calibration_mode(self, mode):
        """Update calibration mode."""
        with self.lock:
            self.data['calibration_mode'] = mode
    
    def update_level_mode(self, mode):
        """Update level mode."""
        with self.lock:
            self.data['level_mode'] = mode
    
    def update_last_good_values(self, values):
        """Update last good values."""
        with self.lock:
            self.data['last_good_values'] = values[:]
    
    def get_all_data(self):
        """Get a snapshot of all data."""
        with self.lock:
            return {
                'val1': self.data['analyzer_1']['values'][0],
                'val2': self.data['analyzer_1']['values'][1],
                'val3': self.data['analyzer_1']['values'][2],
                'val4': self.data['analyzer_2']['values'][0],
                'val5': self.data['analyzer_2']['values'][1],
                'flow': self.data['flow']['value'],
                'analyzer_1_online': self.data['analyzer_1']['online'],
                'analyzer_2_online': self.data['analyzer_2']['online'],
                'flow_online': self.data['flow']['online'],
                'calibration_mode': self.data['calibration_mode'],
                'level_mode': self.data['level_mode'],
                'last_good_values': self.data['last_good_values'][:]
            }

# ============================================================
# READER THREADS
# ============================================================
class Analyzer1Thread(threading.Thread):
    """Thread for reading Analyzer 1 (VAL_1, VAL_2, VAL_3)."""
    
    def __init__(self, shared_data, interval=5):
        super().__init__(name="Analyzer1-Thread", daemon=True)
        self.shared_data = shared_data
        self.interval = interval
        self.running = True
    
    def run(self):
        logger.info(f"🟢 Analyzer 1 thread started (PLC: {ANALYZER_PLC_IP})")
        
        while self.running:
            try:
                values = read_input_registers(ANALYZER_PLC_IP, ANALYZER_1_REGS)
                
                if values is not None:
                    self.shared_data.update_analyzer_1(values, online=True)
                    logger.debug(f"Analyzer 1: VAL_1={values[0]:.2f}, VAL_2={values[1]:.2f}, VAL_3={values[2]:.2f}")
                else:
                    self.shared_data.update_analyzer_1([0.0, 0.0, 0.0], online=False)
                    logger.warning("⚠️ Analyzer 1 offline")
                
            except Exception as e:
                logger.error(f"❌ Analyzer 1 thread error: {e}")
                self.shared_data.update_analyzer_1([0.0, 0.0, 0.0], online=False)
            
            time.sleep(self.interval)
        
        logger.info("🔴 Analyzer 1 thread stopped")
    
    def stop(self):
        self.running = False


class Analyzer2Thread(threading.Thread):
    """Thread for reading Analyzer 2 (VAL_4, VAL_5)."""
    
    def __init__(self, shared_data, interval=5):
        super().__init__(name="Analyzer2-Thread", daemon=True)
        self.shared_data = shared_data
        self.interval = interval
        self.running = True
    
    def run(self):
        logger.info(f"🟢 Analyzer 2 thread started (PLC: {ANALYZER_PLC_IP_2})")
        
        while self.running:
            try:
                values = read_input_registers(ANALYZER_PLC_IP_2, ANALYZER_2_REGS)
                
                if values is not None:
                    self.shared_data.update_analyzer_2(values, online=True)
                    logger.debug(f"Analyzer 2: VAL_4={values[0]:.2f}, VAL_5={values[1]:.2f}")
                else:
                    self.shared_data.update_analyzer_2([0.0, 0.0], online=False)
                    logger.warning("⚠️ Analyzer 2 offline")
                
            except Exception as e:
                logger.error(f"❌ Analyzer 2 thread error: {e}")
                self.shared_data.update_analyzer_2([0.0, 0.0], online=False)
            
            time.sleep(self.interval)
        
        logger.info("🔴 Analyzer 2 thread stopped")
    
    def stop(self):
        self.running = False


class FlowMeterThread(threading.Thread):
    """Thread for reading flow meter."""
    
    def __init__(self, shared_data, interval=5):
        super().__init__(name="FlowMeter-Thread", daemon=True)
        self.shared_data = shared_data
        self.interval = interval
        self.running = True
    
    def run(self):
        logger.info(f"🟢 Flow meter thread started (PLC: {FLOW_PLC_IP})")
        
        while self.running:
            try:
                values = read_input_registers(FLOW_PLC_IP, [FLOW_REG])
                
                if values is not None:
                    self.shared_data.update_flow(values[0], online=True)
                    logger.debug(f"Flow: {values[0]:.2f}")
                else:
                    self.shared_data.update_flow(0.0, online=False)
                    logger.warning("⚠️ Flow meter offline")
                
            except Exception as e:
                logger.error(f"❌ Flow meter thread error: {e}")
                self.shared_data.update_flow(0.0, online=False)
            
            time.sleep(self.interval)
        
        logger.info("🔴 Flow meter thread stopped")
    
    def stop(self):
        self.running = False


class StatusMonitorThread(threading.Thread):
    """Thread for monitoring calibration and level status."""
    
    def __init__(self, shared_data, interval=2):
        super().__init__(name="StatusMonitor-Thread", daemon=True)
        self.shared_data = shared_data
        self.interval = interval
        self.running = True
        self.status_monitor = StatusMonitor(STATUS_PLC_IP)
    
    def run(self):
        logger.info(f"🟢 Status monitor thread started (PLC: {STATUS_PLC_IP})")
        
        while self.running:
            try:
                # Get calibration mode
                cal_mode = self.status_monitor.get_calibration_mode()
                self.shared_data.update_calibration_mode(cal_mode)
                
                # Get level mode
                level_mode = self.status_monitor.get_level_mode()
                self.shared_data.update_level_mode(level_mode)
                
                logger.debug(f"Status: Cal={cal_mode}, Level={level_mode}")
                
            except Exception as e:
                logger.error(f"❌ Status monitor thread error: {e}")
                self.shared_data.update_calibration_mode("IDLE")
                self.shared_data.update_level_mode("IDLE")
            
            time.sleep(self.interval)
        
        self.status_monitor.disconnect()
        logger.info("🔴 Status monitor thread stopped")
    
    def stop(self):
        self.running = False


class DatabaseWriterThread(threading.Thread):
    """Thread for validating data and writing to database."""
    
    def __init__(self, shared_data, interval=60):
        super().__init__(name="DatabaseWriter-Thread", daemon=True)
        self.shared_data = shared_data
        self.interval = interval
        self.running = True
        self.conn = None
    
    def ensure_sql_connection(self):
        """Ensure SQL connection is active."""
        if self.conn is None:
            self.conn = connect_sql()
        return self.conn is not None
    
    def run(self):
        logger.info(f"🟢 Database writer thread started (Interval: {self.interval}s)")
        
        while self.running:
            try:
                if not self.ensure_sql_connection():
                    logger.error("❌ No SQL connection, retrying in next cycle")
                    time.sleep(self.interval)
                    continue
                
                # Get all current data
                data = self.shared_data.get_all_data()
                
                val1 = data['val1']
                val2 = data['val2']
                val3 = data['val3']
                val4 = data['val4']
                val5 = data['val5']
                flow = data['flow']
                calibration_mode = data['calibration_mode']
                level_mode = data['level_mode']
                last_good = data['last_good_values']
                
                # Check if devices are offline
                offline = not (data['analyzer_1_online'] and data['analyzer_2_online'])
                
                # Determine analyzer mode and values to use
                if offline:
                    analyzer_mode = "OFFLINE"
                    is_calibration = 0
                    val1, val2, val3, val4, val5 = last_good
                elif calibration_mode != "IDLE":
                    # In calibration - use last good values
                    analyzer_mode = calibration_mode
                    is_calibration = 1
                    val1, val2, val3, val4, val5 = last_good
                else:
                    # Normal operation - validate values
                    current_values = [val1, val2, val3, val4, val5]
                    if validate_values(current_values):
                        analyzer_mode = "IDLE"
                        self.shared_data.update_last_good_values(current_values)
                    else:
                        analyzer_mode = "INVALID"
                    is_calibration = 0
                
                # Plant status based on flow
                plant_status = "RUNNING" if flow >= FLOW_THRESHOLD else "STOPPED"
                
                # Insert into database
                success = insert_value_record(
                    self.conn,
                    val1, val2, val3, val4, val5,
                    flow,
                    analyzer_mode,
                    level_mode,
                    is_calibration,
                    plant_status
                )
                
                if success:
                    logger.info(
                        f"📊 VAL=[{val1:.2f}, {val2:.2f}, {val3:.2f}, {val4:.2f}, {val5:.2f}] | "
                        f"Flow={flow:.2f} | Mode={analyzer_mode} | Level={level_mode} | "
                        f"Cal={is_calibration} | Plant={plant_status}"
                    )
                else:
                    # Connection might be lost, reset it
                    if self.conn:
                        try:
                            self.conn.close()
                        except:
                            pass
                        self.conn = None
                
            except Exception as e:
                logger.error(f"❌ Database writer thread error: {e}", exc_info=True)
            
            time.sleep(self.interval)
        
        # Cleanup
        if self.conn:
            try:
                self.conn.close()
                logger.info("✅ SQL connection closed")
            except Exception as e:
                logger.error(f"Error closing SQL connection: {e}")
        
        logger.info("🔴 Database writer thread stopped")
    
    def stop(self):
        self.running = False


# ============================================================
# MAIN COORDINATOR
# ============================================================
class AnalyzerMonitor:
    """Main monitoring system coordinator with multi-threading."""
    
    def __init__(self):
        self.shared_data = SharedData()
        self.threads = []
        self.running = False
    
    def start_threads(self):
        """Start all monitoring threads."""
        # Create threads
        analyzer1_thread = Analyzer1Thread(self.shared_data, interval=5)
        analyzer2_thread = Analyzer2Thread(self.shared_data, interval=5)
        flow_thread = FlowMeterThread(self.shared_data, interval=5)
        status_thread = StatusMonitorThread(self.shared_data, interval=2)
        writer_thread = DatabaseWriterThread(self.shared_data, interval=SCAN_INTERVAL)
        
        self.threads = [
            analyzer1_thread,
            analyzer2_thread,
            flow_thread,
            status_thread,
            writer_thread
        ]
        
        # Start all threads
        for thread in self.threads:
            thread.start()
        
        logger.info("✅ All threads started successfully")
    
    def stop_threads(self):
        """Stop all monitoring threads."""
        logger.info("⚠️ Stopping all threads...")
        
        for thread in self.threads:
            if hasattr(thread, 'stop'):
                thread.stop()
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=5)
        
        logger.info("✅ All threads stopped")
    
    def run(self):
        """Main monitoring loop."""
        logger.info("🚀 Combined Analyzer Monitoring System Started (Multi-Threaded)")
        logger.info(f"   Analyzer 1 PLC: {ANALYZER_PLC_IP}")
        logger.info(f"   Analyzer 2 PLC: {ANALYZER_PLC_IP_2}")
        logger.info(f"   Flow PLC: {FLOW_PLC_IP}")
        logger.info(f"   Status PLC: {STATUS_PLC_IP}")
        logger.info(f"   SQL Server: {SQL_SERVER}/{SQL_DATABASE}")
        logger.info(f"   Database Write Interval: {SCAN_INTERVAL} seconds")
        logger.info(f"   Reader Intervals: 5s (analyzers/flow), 2s (status)")
        logger.info("=" * 80)
        
        self.running = True
        
        try:
            self.start_threads()
            
            # Main thread just monitors
            while self.running:
                time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("⚠️ Shutdown requested by user")
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Clean shutdown."""
        logger.info("🛑 Shutting down...")
        self.running = False
        self.stop_threads()
        logger.info("✅ Shutdown complete")

# ============================================================
# ENTRY POINT
# ============================================================
def main():
    """Main entry point."""
    monitor = AnalyzerMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
