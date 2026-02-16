

import os, sys, time, struct, threading, queue, logging
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

import pyodbc
from pymodbus.client import ModbusTcpClient

# ============================================================
# CONFIG
# ============================================================

# ---- SQL ----
SQL_SERVER = os.getenv("SQL_SERVER", "DESKTOP-F4FK4GN")
SQL_DB     = os.getenv("SQL_DB", "DATA")
SQL_UID    = os.getenv("SQL_UID", "Py_User")
SQL_PWD    = os.getenv("SQL_PWD", "Pascal@123")
SQL_DRIVER = os.getenv("SQL_DRIVER", "ODBC Driver 17 for SQL Server")

# ---- Devices ----
STATUS_IP   = "192.168.0.10"   # triggers only
RANGE_IP    = "127.0.0.1"      # expected/min/max holding registers
FLOW_IP     = "192.168.0.14"   # flow input registers

AN1_IP = "192.168.0.4"
AN2_IP = "192.168.0.5"

MODBUS_PORT = 502
MODBUS_TIMEOUT = 3

# ---- Tables ----
T_VALUE_1 = "Value"        # Analyzer-1 historian
T_VALUE_2 = "Value_1"      # Analyzer-2 historian (2 values only)
T_LVL_1   = "LevelCapture"
T_LVL_2   = "LevelCapture_1"
T_CAL_1   = "CAL"
T_CAL_2   = "CAL_1"

# ---- Historian interval ----
HIST_INTERVAL_S = 60
FLOW_STOP_THRESHOLD = 100.0

# ---- Level triggers on STATUS_IP (YOU CONFIRMED DI 3/4/5) ----
LEVEL_DI = {"LOW": 3, "MID": 4, "HIGH": 5}
LEVEL_DELAYS = [120, 10, 10]   # same as your program-2

# ---- Calibration triggers on STATUS_IP ----
CAL_TRIG_AN1 = {
    1201: {"name": "N2O ZERO", "delay": 120, "capture": ["N2O", "NO", "O2"]},
    1202: {"name": "N2O SPAN", "delay": 60,  "capture": ["N2O"]},
    1203: {"name": "NO SPAN",  "delay": 60,  "capture": ["NO"]},
    1204: {"name": "O2 SPAN",  "delay": 30,  "capture": ["O2"]},
}
CAL_TRIG_AN2 = {
    1201: {"name": "N2O ZERO", "delay": 120, "capture": ["N2O", "NO"]},  # ✅ O2 skipped
    1202: {"name": "N2O SPAN", "delay": 60,  "capture": ["N2O"]},
    1203: {"name": "NO SPAN",  "delay": 60,  "capture": ["NO"]},
}

# ---- Analyzer input registers (live values) ----
# Same order as your core program
AN1_LIVE_REGS = [ (0, "ABCD"), (2, "CDAB"), (6, "ABCD") ]  # N2O, NO, O2
AN2_LIVE_REGS = [ (0, "ABCD"), (2, "CDAB") ]              # N2O, NO

FLOW_REGS = [ (1, "ABCD") ]  # flow

# ---- Range maps (expected/min/max addresses on RANGE_IP holding regs) ----
# Each entry: (measured_input_reg, measured_order, expected_reg, min_reg, max_reg, factor)
AN1_RANGE_MAP = {
    "N2O": (0, "ABCD", 124, 100, 102, 100),
    "NO":  (2, "CDAB", 126, 104, 106, 101),
    "O2":  (6, "ABCD", 128, 108, 110, 102),
}

# ✅ As you provided for Analyzer-2:
# N2O: min=114 max=116 expected=130
# NO : min=118 max=120 expected=132
# N2O mid cylinder: max=122 (expected unknown -> we’ll use expected=None; for ZERO/SPAN/NO this is not used)
AN2_RANGE_MAP = {
    "N2O": (0, "ABCD", 130, 114, 116, 100),
    "NO":  (2, "CDAB", 132, 118, 120, 101),
}

# Historian MIN checks (MIN-only invalid rule) – read from holding registers
AN1_MIN_MAP = {
    1: {"ip": RANGE_IP, "reg": 100, "order": "CDAB"},  # VAL_1 min
    2: {"ip": RANGE_IP, "reg": 104, "order": "CDAB"},  # VAL_2 min
    3: {"ip": RANGE_IP, "reg": 108, "order": "CDAB"},  # VAL_3 min
    4: {"ip": RANGE_IP, "reg": 112, "order": "CDAB"},  # VAL_4 min (if exists)
    5: {"ip": RANGE_IP, "reg": 118, "order": "CDAB"},  # VAL_5 min (if exists)
}
AN2_MIN_MAP = {
    1: {"ip": RANGE_IP, "reg": 114, "order": "CDAB"},  # N2O min
    2: {"ip": RANGE_IP, "reg": 118, "order": "CDAB"},  # NO min
}

# Analyzer-2 LevelCapture reference expected values (from RANGE_IP holding regs)
# Map level trigger -> which expected value to compare against (you said actual reference comes from that table)
AN2_LEVEL_REF = {
    "LOW": {"expected_reg": 130, "order": "CDAB"},  # N2O expected
    "MID": {"expected_reg": 132, "order": "CDAB"},  # NO expected (if your MID corresponds to NO; adjust if needed)
    "HIGH": {"expected_reg": 130, "order": "CDAB"}, # default N2O expected (adjust if needed)
}
# If you want MID = N2O mid cylinder max 122, set expected_reg to 122 and order CDAB.
# Example: AN2_LEVEL_REF["MID"] = {"expected_reg": 122, "order":"CDAB"}

# Analyzer-1 LevelCapture actual references (legacy from your program-2)
AN1_ACTUAL_REF = {
    "LOW":  None,
    "MID":  111,
    "HIGH": 123
}

# Byte order used to decode RANGE_IP holding floats
RANGE_HOLDING_ORDER_DEFAULT = "CDAB"

# Addressing note:
# If your RANGE_IP device requires (address-1), set this to 1, else 0.
RANGE_ADDR_OFFSET = 0  # your earlier code used address-1

# ============================================================
# LOGGING
# ============================================================

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    lg = logging.getLogger("combined")
    lg.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s")

    fh = RotatingFileHandler("logs/combined_service.log", maxBytes=5_000_000, backupCount=10, encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.INFO)

    eh = TimedRotatingFileHandler("logs/combined_errors.log", when="midnight", interval=1, backupCount=10, encoding="utf-8")
    eh.setFormatter(fmt)
    eh.setLevel(logging.WARNING)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.INFO)

    lg.handlers = [fh, eh, ch]
    return lg

logger = setup_logger()

# ============================================================
# SQL
# ============================================================

def sql_connect():
    conn_str = (
        f"Driver={{{SQL_DRIVER}}};"
        f"Server={SQL_SERVER};"
        f"Database={SQL_DB};"
        f"UID={SQL_UID};PWD={SQL_PWD};"
        f"TrustServerCertificate=yes;"
    )
    return pyodbc.connect(conn_str, timeout=10)

def ensure_tables():
    """
    Creates tables if missing and adds Plant_Status to historians.
    Safe to run every start.
    """
    ddl_value = f"""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '{T_VALUE_1}')
    BEGIN
      CREATE TABLE {T_VALUE_1}(
        [DATE] DATETIME NOT NULL,
        VAL_1 FLOAT NULL, VAL_2 FLOAT NULL, VAL_3 FLOAT NULL, VAL_4 FLOAT NULL, VAL_5 FLOAT NULL,
        Flow FLOAT NULL,
        Analyzer_Mode VARCHAR(50) NULL,
        Level_Mode VARCHAR(50) NULL,
        IsCalibration BIT NOT NULL DEFAULT 0,
        Plant_Status VARCHAR(20) NOT NULL DEFAULT 'PLANT STOP'
      )
    END
    ELSE
    BEGIN
      IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name='Plant_Status' AND Object_ID=Object_ID('{T_VALUE_1}'))
        ALTER TABLE {T_VALUE_1} ADD Plant_Status VARCHAR(20) NOT NULL DEFAULT 'PLANT STOP';
    END
    """
    ddl_value2 = ddl_value.replace(T_VALUE_1, T_VALUE_2)

    ddl_level = f"""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '{T_LVL_1}')
    BEGIN
      CREATE TABLE {T_LVL_1}(
        [Timestamp] DATETIME NOT NULL,
        LevelName VARCHAR(50) NOT NULL,
        ValueType VARCHAR(50) NOT NULL,
        Value FLOAT NULL
      )
    END
    """
    ddl_level2 = ddl_level.replace(T_LVL_1, T_LVL_2)

    ddl_cal = f"""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = '{T_CAL_1}')
    BEGIN
      CREATE TABLE {T_CAL_1}(
        [DATE] DATETIME NOT NULL,
        CAL_NAME VARCHAR(50) NOT NULL,
        NAME VARCHAR(50) NOT NULL,
        VAL FLOAT NULL,
        EXPECTED FLOAT NULL,
        ERROR FLOAT NULL,
        ACCURACY FLOAT NULL,
        STATUS VARCHAR(50) NULL
      )
    END
    """
    ddl_cal2 = ddl_cal.replace(T_CAL_1, T_CAL_2)

    try:
        conn = sql_connect()
        cur = conn.cursor()
        for ddl in [ddl_value, ddl_value2, ddl_level, ddl_level2, ddl_cal, ddl_cal2]:
            cur.execute(ddl)
        conn.commit()
        cur.close()
        conn.close()
        logger.info("SQL tables ensured")
    except Exception as e:
        logger.warning(f"ensure_tables failed: {e}")

class SQLWriter(threading.Thread):
    """
    One SQL writer thread, batched inserts, low CPU.
    Queue item: {"sql": "...", "params": tuple()}
    """
    def __init__(self, q: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True, name="SQLWriter")
        self.q = q
        self.stop_event = stop_event
        self.conn = None

    def run(self):
        while not self.stop_event.is_set():
            try:
                if self.conn is None:
                    self.conn = sql_connect()
                    logger.info("SQLWriter connected")

                batch = []
                try:
                    item = self.q.get(timeout=1)
                    batch.append(item)
                    while len(batch) < 300:
                        try:
                            batch.append(self.q.get_nowait())
                        except queue.Empty:
                            break
                except queue.Empty:
                    continue

                cur = self.conn.cursor()
                for it in batch:
                    cur.execute(it["sql"], it["params"])
                self.conn.commit()
            except pyodbc.Error as e:
                logger.warning(f"SQLWriter error: {e} -> reconnect")
                try:
                    if self.conn:
                        self.conn.close()
                except Exception:
                    pass
                self.conn = None
                time.sleep(5)
            except Exception as e:
                logger.warning(f"SQLWriter unexpected: {e}")
                time.sleep(1)

        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        logger.info("SQLWriter stopped")

# ============================================================
# MODBUS (Optimized shared clients per IP)
# ============================================================

def decode_float(w1, w2, order="ABCD"):
    b1 = struct.pack(">H", w1)
    b2 = struct.pack(">H", w2)
    if order == "ABCD":
        data = b1 + b2
    elif order == "CDAB":
        data = b2 + b1
    elif order == "BADC":
        data = b1[::-1] + b2[::-1]
    elif order == "DCBA":
        data = b2[::-1] + b1[::-1]
    else:
        data = b1 + b2
    return struct.unpack(">f", data)[0]

class SharedModbus:
    """One ModbusTcpClient per IP with a lock; reconnect on failure."""
    def __init__(self, host: str):
        self.host = host
        self.lock = threading.RLock()
        self.client = None
        self.last_fail = 0

    def _connect(self):
        try:
            if self.client:
                try: self.client.close()
                except Exception: pass
            self.client = ModbusTcpClient(self.host, port=MODBUS_PORT, timeout=MODBUS_TIMEOUT)
            return self.client.connect()
        except Exception:
            return False

    def _ensure(self):
        if self.client and getattr(self.client, "connected", False):
            return True
        # throttle reconnect attempts
        now = time.time()
        if now - self.last_fail < 1.5:
            return False
        ok = self._connect()
        if not ok:
            self.last_fail = now
        return ok

    def read_discrete(self, address: int, count: int = 1):
        with self.lock:
            if not self._ensure():
                return None
            try:
                r = self.client.read_discrete_inputs(address=address, count=count)
                if r.isError():
                    return None
                return r.bits
            except Exception:
                self.last_fail = time.time()
                return None

    def read_input_regs(self, address: int, count: int):
        with self.lock:
            if not self._ensure():
                return None
            try:
                r = self.client.read_input_registers(address=address, count=count)
                if r.isError():
                    return None
                return r.registers
            except Exception:
                self.last_fail = time.time()
                return None

    def read_holding_regs(self, address: int, count: int):
        with self.lock:
            if not self._ensure():
                return None
            try:
                r = self.client.read_holding_registers(address=address, count=count)
                if r.isError():
                    return None
                return r.registers
            except Exception:
                self.last_fail = time.time()
                return None

# Shared clients
MB_STATUS = SharedModbus(STATUS_IP)
MB_RANGE  = SharedModbus(RANGE_IP)
MB_FLOW   = SharedModbus(FLOW_IP)
MB_AN1    = SharedModbus(AN1_IP)
MB_AN2    = SharedModbus(AN2_IP)

# ============================================================
# RANGE CACHE (reduces modbus reads)
# ============================================================

class RangeCache:
    def __init__(self, ttl_s=5):
        self.ttl = ttl_s
        self.lock = threading.RLock()
        self.cache = {}  # key -> (ts, value)

    def get_float_holding(self, reg: int, order="CDAB"):
        # handle RANGE_ADDR_OFFSET
        addr = reg - RANGE_ADDR_OFFSET if RANGE_ADDR_OFFSET else reg

        key = (addr, order)
        now = time.time()
        with self.lock:
            if key in self.cache:
                ts, val = self.cache[key]
                if now - ts <= self.ttl:
                    return val

        regs = MB_RANGE.read_holding_regs(addr, 2)
        if not regs or len(regs) < 2:
            return None
        val = decode_float(regs[0], regs[1], order)

        with self.lock:
            self.cache[key] = (now, val)
        return val

RANGE_CACHE = RangeCache(ttl_s=5)

# ============================================================
# COMMON HELPERS
# ============================================================

def plant_status(flow_val: float) -> str:
    return "PLANT RUNNING" if (flow_val is not None and flow_val >= FLOW_STOP_THRESHOLD) else "PLANT STOP"

def read_block_input(mb: SharedModbus, reg_map):
    """Read a single input-register block then decode floats. Returns list or None if offline."""
    max_reg = max(a for a, _ in reg_map) + 2
    regs = mb.read_input_regs(0, max_reg)
    if not regs:
        return None
    out = []
    for addr, fmt in reg_map:
        try:
            out.append(decode_float(regs[addr], regs[addr+1], fmt))
        except Exception:
            out.append(0.0)
    return out

def read_flow():
    vals = read_block_input(MB_FLOW, FLOW_REGS)
    return vals[0] if vals else 0.0

def read_bit_status(di_addr: int) -> bool | None:
    bits = MB_STATUS.read_discrete(di_addr, 1)
    if bits is None:
        return None
    return bool(bits[0])

# ============================================================
# PROGRAM-1 & PROGRAM-2: HISTORIANS
# ============================================================

class Historian(threading.Thread):
    """
    Historian for one analyzer.
    - Reads live values
    - Uses calibration triggers to freeze
    - Handles OFFLINE
    - Handles INVALID (MIN-only, MIN from RANGE_IP holding regs)
    - Writes to Value table
    """
    def __init__(self, name, mb_an, live_regs, min_map, table, sql_q: queue.Queue, stop_event: threading.Event, val_count=5):
        super().__init__(daemon=True, name=name)
        self.mb_an = mb_an
        self.live_regs = live_regs
        self.min_map = min_map
        self.table = table
        self.sql_q = sql_q
        self.stop_event = stop_event
        self.val_count = val_count
        self.last_good = [0.0] * val_count

    def _is_calibration(self) -> tuple[str, int]:
        # If any of trigger bits active => calibration mode string
        # Analyzer-1 uses 1201..1204; Analyzer-2 uses 1201..1203 (still OK: 1204 won't be used elsewhere)
        active = []
        for addr, mode in [(1201, "N2O ZERO"), (1202, "N2O SPAN"), (1203, "NO SPAN"), (1204, "O2 SPAN")]:
            b = read_bit_status(addr)
            if b:
                active.append(mode)
        if active:
            return active[0], 1
        return "ANALYZER IDLE", 0

    def _level_mode(self) -> str:
        # Optional: level mode indicator based on DI 3/4/5
        for nm, addr in [("LOW LEVEL", LEVEL_DI["LOW"]), ("MID LEVEL", LEVEL_DI["MID"]), ("HIGH LEVEL", LEVEL_DI["HIGH"])]:
            b = read_bit_status(addr)
            if b:
                return nm
        return "LEVEL IDLE"

    def _invalid_min_only(self, values):
        # ONLY check values against MIN (if value < MIN => invalid)
        for idx, v in enumerate(values, start=1):
            cfg = self.min_map.get(idx)
            if not cfg:
                continue
            mn = RANGE_CACHE.get_float_holding(cfg["reg"], cfg.get("order", RANGE_HOLDING_ORDER_DEFAULT))
            if mn is not None and v < mn:
                return True
        return False

    def run(self):
        logger.info(f"{self.name} started")
        while not self.stop_event.is_set():
            try:
                flow = read_flow()
                pstat = plant_status(flow)

                analyzer_mode, is_cal = self._is_calibration()
                level_mode = self._level_mode()

                new_vals = read_block_input(self.mb_an, self.live_regs)
                if new_vals is None:
                    analyzer_mode = "ANALYZER OFFLINE"
                    is_cal = 0
                    new_vals = self.last_good[:]
                else:
                    # Ensure correct length
                    new_vals = (new_vals + [None]*self.val_count)[:self.val_count]

                    if analyzer_mode == "ANALYZER IDLE":
                        if self._invalid_min_only(new_vals):
                            analyzer_mode = "ANALYZER INVALID"
                        else:
                            self.last_good = new_vals[:]
                    else:
                        # Calibration freeze
                        new_vals = self.last_good[:]

                # For analyzer-2 historian: store only 2 values; rest NULL
                vals_for_sql = (new_vals + [None]*5)[:5]

                sql = f"""
                INSERT INTO {self.table}
                ([DATE], VAL_1, VAL_2, VAL_3, VAL_4, VAL_5, Flow,
                 Analyzer_Mode, Level_Mode, IsCalibration, Plant_Status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = (datetime.now(), *vals_for_sql, float(flow), analyzer_mode, level_mode, int(is_cal), pstat)
                self.sql_q.put({"sql": sql, "params": params})

                logger.info(f"{self.name} -> MODE={analyzer_mode} PLANT={pstat} FLOW={flow} VALS={vals_for_sql[:self.val_count]}")
            except Exception as e:
                logger.warning(f"{self.name} error: {e}")

            # Sleep with responsiveness
            for _ in range(int(HIST_INTERVAL_S*10)):
                if self.stop_event.is_set():
                    break
                time.sleep(0.1)

        logger.info(f"{self.name} stopped")

# ============================================================
# PROGRAM-1 & PROGRAM-2: LEVEL CAPTURE
# ============================================================

def sql_put_level(sql_q, table, ts, level_name, value_type, value):
    sql = f"INSERT INTO {table} ([Timestamp],[LevelName],[ValueType],[Value]) VALUES (?,?,?,?)"
    sql_q.put({"sql": sql, "params": (ts, level_name, value_type, value)})

def read_input_float(mb: SharedModbus, address: int, order="ABCD"):
    regs = mb.read_input_regs(address, 2)
    if not regs or len(regs) < 2:
        return None
    return decode_float(regs[0], regs[1], order)

def read_holding_float_cached(reg: int, order="CDAB"):
    return RANGE_CACHE.get_float_holding(reg, order)

def level_capture_worker(name, mb_an, table, sql_q, level_key: str, actual_ref_mode: str):
    """
    actual_ref_mode:
      - "AN1_LEGACY": uses AN1_ACTUAL_REF registers on RANGE_IP holding floats
      - "AN2_EXPECTED": uses expected values (130/132/...) on RANGE_IP holding floats
    """
    thread_name = f"{name}-CAP-{level_key}"
    threading.current_thread().name = thread_name
    try:
        level_name = f"{level_key.title()} Level"
        logger.info(f"[{thread_name}] started")

        vals = []
        for i, delay_s in enumerate(LEVEL_DELAYS, start=1):
            time.sleep(delay_s)
            v = read_input_float(mb_an, 0, "ABCD")  # same as your old VALUE_REGISTER=0
            ts = datetime.now()
            if v is not None:
                vals.append(float(v))
                sql_put_level(sql_q, table, ts, level_name, f"Val {i}", float(v))
                logger.info(f"[{thread_name}] Read {i}: {v}")
            else:
                logger.warning(f"[{thread_name}] Read {i} failed")

        if not vals:
            logger.warning(f"[{thread_name}] no readings; exit")
            return

        avg_val = sum(vals) / len(vals)
        sql_put_level(sql_q, table, datetime.now(), level_name, "Avg", float(avg_val))

        # actual reference
        if actual_ref_mode == "AN1_LEGACY":
            reg = AN1_ACTUAL_REF.get(level_key.upper())
            if reg is None:
                actual_val = 0.0
            else:
                actual_val = read_holding_float_cached(reg, "CDAB")
                if actual_val is None:
                    actual_val = 0.0
        else:
            cfg = AN2_LEVEL_REF.get(level_key.upper())
            if cfg:
                actual_val = read_holding_float_cached(cfg["expected_reg"], cfg.get("order","CDAB"))
                if actual_val is None:
                    actual_val = 0.0
            else:
                actual_val = 0.0

        err = avg_val - actual_val
        pct = ((err / actual_val) * 100.0) if actual_val != 0 else 0.0

        t = datetime.now()
        sql_put_level(sql_q, table, t, level_name, "Actual", float(actual_val))
        sql_put_level(sql_q, table, t, level_name, "Error", float(err))
        sql_put_level(sql_q, table, t, level_name, "% Error", float(pct))

        logger.info(f"[{thread_name}] Avg={avg_val:.4f} Actual={actual_val:.4f} Err={err:.4f} %={pct:.2f}")
        logger.info(f"[{thread_name}] finished")

    except Exception as e:
        logger.warning(f"[{thread_name}] error: {e}")

class LevelMonitor(threading.Thread):
    def __init__(self, name, mb_an, table, sql_q, stop_event, actual_ref_mode):
        super().__init__(daemon=True, name=name)
        self.mb_an = mb_an
        self.table = table
        self.sql_q = sql_q
        self.stop_event = stop_event
        self.actual_ref_mode = actual_ref_mode
        self.last = {k: False for k in LEVEL_DI.keys()}

    def run(self):
        logger.info(f"{self.name} started")
        while not self.stop_event.is_set():
            try:
                for key, di in LEVEL_DI.items():
                    st = read_bit_status(di)
                    if st is None:
                        continue

                    if st and not self.last[key]:
                        threading.Thread(
                            target=level_capture_worker,
                            args=(self.name, self.mb_an, self.table, self.sql_q, key, self.actual_ref_mode),
                            daemon=True
                        ).start()

                    self.last[key] = bool(st)
            except Exception as e:
                logger.warning(f"{self.name} error: {e}")

            time.sleep(0.5)
        logger.info(f"{self.name} stopped")

# ============================================================
# PROGRAM-1 & PROGRAM-2: CALIBRATION ENGINE
# ============================================================

def read_expected_min_max(range_map, tag: str):
    _, _, exp_reg, min_reg, max_reg, _ = range_map[tag]
    exp = read_holding_float_cached(exp_reg, "CDAB") if exp_reg else None
    mn  = read_holding_float_cached(min_reg, "CDAB") if min_reg else None
    mx  = read_holding_float_cached(max_reg, "CDAB") if max_reg else None
    return exp, mn, mx

def read_measured(mb_an: SharedModbus, range_map, tag: str):
    in_reg, fmt, *_ = range_map[tag]
    regs = mb_an.read_input_regs(in_reg, 2)
    if not regs or len(regs) < 2:
        return None
    return decode_float(regs[0], regs[1], fmt)

def evaluate(tag, val, cal_name, range_map):
    _, _, _, _, _, factor = range_map[tag]

    if cal_name == "N2O ZERO":
        expected = 0.0
        min_r = -0.2
        max_r = 0.2
    else:
        expected, min_r, max_r = read_expected_min_max(range_map, tag)
        if expected is None or min_r is None or max_r is None:
            return (None, None, None, "READ ERROR")

    error = val - expected
    accuracy = (abs(error) / expected * factor) if expected not in (None, 0) else (abs(val) * factor)
    status = "CAL OK" if (min_r is not None and max_r is not None and min_r <= val <= max_r) else "OUT OF CONTROL"
    return (expected, error, accuracy, status)

class CalWorker(threading.Thread):
    def __init__(self, name, trig_addr, trig_info, mb_an, table, range_map, sql_q, stop_event):
        super().__init__(daemon=True, name=f"{name}-{trig_info['name']}")
        self.name_prefix = name
        self.trig_addr = trig_addr
        self.info = trig_info
        self.mb_an = mb_an
        self.table = table
        self.range_map = range_map
        self.sql_q = sql_q
        self.stop_event = stop_event

    def run(self):
        cal_name = self.info["name"]
        delay = self.info["delay"]
        tags = self.info["capture"]

        logger.info(f"{self.name} triggered -> wait {delay}s")
        end = time.time() + delay
        while time.time() < end and not self.stop_event.is_set():
            time.sleep(0.2)

        while not self.stop_event.is_set():
            active = read_bit_status(self.trig_addr)
            if not active:
                logger.info(f"{self.name} ended")
                break

            ts = datetime.now()
            for tag in tags:
                if tag not in self.range_map:
                    continue
                val = read_measured(self.mb_an, self.range_map, tag)
                if val is None:
                    continue

                expected, err, acc, status = evaluate(tag, val, cal_name, self.range_map)

                sql = f"""
                INSERT INTO {self.table} (DATE, CAL_NAME, NAME, VAL, EXPECTED, ERROR, ACCURACY, STATUS)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = (ts, cal_name, tag, float(val), expected, err, acc, status)
                self.sql_q.put({"sql": sql, "params": params})

                logger.info(f"{self.name} {tag}: val={val:.3f} exp={expected} err={err} acc={acc} status={status}")

            time.sleep(CAPTURE_INTERVAL_S)

class CalMonitor(threading.Thread):
    def __init__(self, name, trig_map, mb_an, table, range_map, sql_q, stop_event):
        super().__init__(daemon=True, name=name)
        self.trig_map = trig_map
        self.mb_an = mb_an
        self.table = table
        self.range_map = range_map
        self.sql_q = sql_q
        self.stop_event = stop_event
        self.last = {k: False for k in trig_map.keys()}
        self.workers = {}

    def run(self):
        logger.info(f"{self.name} started")
        while not self.stop_event.is_set():
            try:
                for addr, info in self.trig_map.items():
                    st = read_bit_status(addr)
                    if st is None:
                        continue

                    if st and not self.last[addr]:
                        w = self.workers.get(addr)
                        if not w or not w.is_alive():
                            w = CalWorker(self.name, addr, info, self.mb_an, self.table, self.range_map, self.sql_q, self.stop_event)
                            self.workers[addr] = w
                            w.start()

                    self.last[addr] = bool(st)

            except Exception as e:
                logger.warning(f"{self.name} error: {e}")

            time.sleep(0.5)
        logger.info(f"{self.name} stopped")

# ============================================================
# MAIN
# ============================================================

CAPTURE_INTERVAL_S = 10  # calibration capture interval

def main():
    stop_event = threading.Event()
    sql_q = queue.Queue(maxsize=50000)

    ensure_tables()

    sql_writer = SQLWriter(sql_q, stop_event)

    # Historians
    hist1 = Historian("AN1-HIST", MB_AN1, AN1_LIVE_REGS, AN1_MIN_MAP, T_VALUE_1, sql_q, stop_event, val_count=3)
    hist2 = Historian("AN2-HIST", MB_AN2, AN2_LIVE_REGS, AN2_MIN_MAP, T_VALUE_2, sql_q, stop_event, val_count=2)

    # Level monitors
    lvl1 = LevelMonitor("AN1-LVL", MB_AN1, T_LVL_1, sql_q, stop_event, actual_ref_mode="AN1_LEGACY")
    lvl2 = LevelMonitor("AN2-LVL", MB_AN2, T_LVL_2, sql_q, stop_event, actual_ref_mode="AN2_EXPECTED")

    # Calibration monitors
    cal1 = CalMonitor("AN1-CAL", CAL_TRIG_AN1, MB_AN1, T_CAL_1, AN1_RANGE_MAP, sql_q, stop_event)
    cal2 = CalMonitor("AN2-CAL", CAL_TRIG_AN2, MB_AN2, T_CAL_2, AN2_RANGE_MAP, sql_q, stop_event)

    threads = [sql_writer, hist1, hist2, lvl1, lvl2, cal1, cal2]
    for t in threads:
        t.start()

    logger.info("✅ Combined optimized service running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.warning("Stopping...")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=5)
        logger.info("✅ Clean exit")

if __name__ == "__main__":
    main()
