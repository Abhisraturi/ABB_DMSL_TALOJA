import struct
import logging
from logging.handlers import TimedRotatingFileHandler
from pymodbus.client import ModbusTcpClient
from time import sleep
import pyodbc
import time
from datetime import datetime
import os

# ----------------------------
# Logging setup
# ----------------------------
def setup_logger():
    logger = logging.getLogger("PLC_Logger")
    logger.setLevel(logging.INFO)

    handler = TimedRotatingFileHandler(
        "Analyser_Tcp_IP_error_log.log",
        when="midnight",
        interval=1,
        backupCount=1,
        encoding="utf-8"
    )
    handler.setLevel(logging.WARNING)

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)

    if not logger.handlers:
        logger.addHandler(handler)
        logger.addHandler(console)
    else:
        logger.handlers = [handler, console]

    return logger

logger = setup_logger()

# ----------------------------
# SQL Server functions
# ----------------------------
def init_db_sqlserver(server_name, database_name, uid, pwd, table_name="Value"):
    conn_str = (
        f"Driver={{ODBC Driver 17 for SQL Server}};"
        f"Server={server_name};"
        f"Database={database_name};"
        f"UID={uid};"
        f"PWD={pwd};"
        f"TrustServerCertificate=yes;"
    )
    conn = pyodbc.connect(conn_str, timeout=10)
    cursor = conn.cursor()

    # ⭐ NEW COLUMN Flow added
    cursor.execute(f"""
        IF NOT EXISTS (
            SELECT * FROM sys.tables WHERE name = '{table_name}'
        )
        CREATE TABLE {table_name} (
            [DATE] DATETIME NOT NULL,
            VAL_1 FLOAT NULL,
            VAL_2 FLOAT NULL,
            VAL_3 FLOAT NULL,
            VAL_4 FLOAT NULL,
            VAL_5 FLOAT NULL,
            Flow FLOAT NULL     -- ⭐ NEW
        )
        ELSE
        BEGIN
            IF NOT EXISTS(SELECT * FROM sys.columns WHERE Name='Flow' AND Object_ID=Object_ID('{table_name}'))
            ALTER TABLE {table_name} ADD Flow FLOAT NULL;
        END
    """)
    conn.commit()
    cursor.close()
    return conn


def connect_with_retry(server_name, database_name, uid, pwd, retries=15, delay=10):
    for attempt in range(1, retries + 1):
        try:
            conn = init_db_sqlserver(server_name, database_name, uid, pwd)
            logger.info(f"SQL connection established on attempt {attempt}")
            return conn
        except Exception as e:
            logger.warning(f"SQL connection attempt {attempt}/{retries} failed: {e}")
            try:
                time.sleep(delay)
            except KeyboardInterrupt:
                logger.warning("KeyboardInterrupt during retry")
                raise
    logger.error("Could not connect to SQL Server.")
    return None


def store_values_sqlserver(conn, values, Flow_value, table_name="Value"):   # ⭐ NEW PARAM Flow_value
    cursor = conn.cursor()
    timestamp = datetime.now()

    vals_to_store = values + [None] * (5 - len(values))  # keep old logic

    try:
        cursor.execute(
            f"INSERT INTO {table_name} ([DATE], VAL_1, VAL_2, VAL_3, VAL_4, VAL_5, Flow) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, *vals_to_store[:5], Flow_value)
        )
        conn.commit()
    except pyodbc.Error as e:
        logger.warning(f"DB write failed: {e}. Reconnecting...")
        try:
            conn.close()
        except:
            pass
        raise
    finally:
        try:
            cursor.close()
        except:
            pass


# ----------------------------
# Modbus decode helpers
# ----------------------------
def decode_float(w1, w2, order="ABCD"):
    b1 = struct.pack('>H', w1)
    b2 = struct.pack('>H', w2)

    if order == "ABCD":
        data = b1 + b2
    elif order == "CDAB":
        data = b2 + b1
    elif order == "BADC":
        data = b1[::-1] + b2[::-1]
    elif order == "DCBA":
        data = b2[::-1] + b1[::-1]
    else:
        raise ValueError("Unknown byte order")

    return struct.unpack('>f', data)[0]


def read_registers(ip, reg_map, slave_id=1):
    client = ModbusTcpClient(host=ip, port=502, timeout=3)
    decoded = []

    if not client.connect():
        logger.warning(f"Could not connect to PLC {ip}")
        return [0.0] * len(reg_map)

    try:
        max_reg = max(i for i, _ in reg_map) + 2
        response = client.read_input_registers(address=0, count=max_reg)
        if response.isError():
            logger.warning(f"Error reading from PLC {ip}")
            return [0.0] * len(reg_map)

        words = response.registers
        for i, fmt in reg_map:
            if i + 1 >= len(words):
                logger.warning(f"Not enough registers at {ip} index {i}")
                decoded.append(0.0)
                continue
            try:
                val = decode_float(words[i], words[i + 1], fmt)
                decoded.append(val)
            except Exception as e:
                logger.warning(f"Decode error {ip} reg {i}: {e}")
                decoded.append(0.0)
    finally:
        client.close()

    return decoded


# ----------------------------
# SQL Auth Credentials
# ----------------------------
SQL_UID = os.getenv("SQL_UID", "Py_User")
SQL_PWD = os.getenv("SQL_PWD", "Pascal@123")
server_name = "DESKTOP-F4FK4GN"
database_name = "DATA"

conn = connect_with_retry(server_name, database_name, SQL_UID, SQL_PWD)

# ----------------------------
# Main Loop
# ----------------------------
def main():
    global conn

    plc_list = [
        {"ip": "192.168.0.4", "regs": [(0, "ABCD"), (2, "CDAB"), (6, "ABCD")]},
        {"ip": "192.168.0.5", "regs": [(0, "ABCD"), (2, "CDAB")]}
    ]

    # ⭐ NEW PLC (Flow)
    Flow_plc = {"ip": "192.168.0.14", "regs": [(1, "ABCD")]}

    logger.info("Starting 24x7 Modbus monitoring...")

    while True:
        try:
            all_values = []

            # Read existing PLC list
            for plc in plc_list:
                vals = read_registers(plc["ip"], plc["regs"])
                all_values.extend(vals)

            # ⭐ Read Flow PLC (Fail-safe)
            Flow_read = read_registers(Flow_plc["ip"], Flow_plc["regs"])
            Flow_value = Flow_read[0] if Flow_read else 0.0

            # If connection failed, place 0
            if Flow_value is None or isinstance(Flow_value, str):
                Flow_value = 0.0

            if Flow_value == 0.0:
                logger.warning("Flow read failed — storing 0")


            logger.info(f"Read Values: {all_values} | Flow = {Flow_value}")

            if conn is None:
                conn = connect_with_retry(server_name, database_name, SQL_UID, SQL_PWD)

            try:
                if conn:
                    store_values_sqlserver(conn, all_values, Flow_value)
                else:
                    logger.warning("No DB connection — skipping write.")
            except pyodbc.Error:
                conn = connect_with_retry(server_name, database_name, SQL_UID, SQL_PWD)
                if conn:
                    store_values_sqlserver(conn, all_values, Flow_value)

        except KeyboardInterrupt:
            logger.info("Stopped manually.")
            break
        except Exception as e:
            logger.warning(f"Unexpected error: {e}")

        sleep(60)


if __name__ == "__main__":
    main()
