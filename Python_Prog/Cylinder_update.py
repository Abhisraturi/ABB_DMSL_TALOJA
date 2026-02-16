import pyodbc
from datetime import datetime
import sys

# --- CONFIGURATION ---
server = 'DESKTOP-F4FK4GN'
database = 'DATA'
username = 'Py_User'
password = 'Pascal@123' 

# Standard SQL Server Driver
conn_str = (
    f'DRIVER={{SQL Server}};'
    f'SERVER={server};'
    f'DATABASE={database};'
    f'UID={username};'
    f'PWD={password};'
)

def exit_program(message):
    print(f"\n❌ {message}")
    input("\nPress Enter to exit...")
    sys.exit()

def update_cylinder():
    conn = None
    try:
        print("Connecting to database... please wait.")
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()

        print("\n--- SELECT ANALYSER ---")
        print("1. Analyser-N2O Abator Inlet")
        print("2. Analyser-N2O Abator Outlet (Stack)")
        
        analyser_choice = input("Enter Choice (1 or 2): ")
        
        if analyser_choice == "1":
            target_table = "[dbo].[Cylinder_detail_Cal]"
            loc_name = "Inlet"
        elif analyser_choice == "2":
            target_table = "[dbo].[Cylinder_detail_Cal_1]"
            loc_name = "Outlet (Stack)"
        else:
            exit_program("Invalid Selection.")

        print(f"\n--- Updating {loc_name} Calibration ---")
        print("1. Zero calibration")
        print("2. N2O SPAN calibration")
        print("3. N2O Mid calibration")
        
        cal_choice = input("Select Calibration Type (1-3): ")
        cal_map = {"1": "Zero calibration", "2": "N2O SPAN calibration", "3": "N2O Mid calibration"}
        
        if cal_choice not in cal_map:
            exit_program("Invalid Calibration Type.")

        calibration = cal_map[cal_choice]

        # Fetch Last Expiration Date
        last_date_query = f"SELECT TOP 1 Exp_Date FROM {target_table} WHERE Calibration = ? ORDER BY Update_Timestamp DESC"
        cursor.execute(last_date_query, (calibration,))
        row = cursor.fetchone()
        last_exp_str = row[0] if row else "1900-01-01"

        # Data Entry
        cyl_num = input(f"Enter Cylinder Number: ").strip()
        exp_date_input = input(f"Enter Expiration Date (YYYY-MM-DD) [Must be > {last_exp_str}]: ").strip()
        concentration_input = input(f"Enter Concentration: ").strip()

        # Validation 1: Nulls
        if not cyl_num or not exp_date_input or not concentration_input:
            exit_program("Failed: Null values are not allowed.")

        # Validation 2: Must start with a number
        if not concentration_input[0].isdigit():
            exit_program("Failed: Concentration must start with a number (0-9).")

        # Validation 3: Date check
        try:
            new_date = datetime.strptime(exp_date_input, '%Y-%m-%d')
            try:
                last_date = datetime.strptime(last_exp_str, '%Y-%m-%d')
            except ValueError:
                last_date = datetime.min
            
            if new_date <= last_date:
                exit_program(f"Failed: New Expiration Date must be greater than {last_exp_str}.")
        except ValueError:
            exit_program("Failed: Date must be in YYYY-MM-DD format.")

        # SQL Execution
        query = f"INSERT INTO {target_table} ([Update_Timestamp], [Calibration], [Cylinder_Number], [Exp_Date], [Concentration]) VALUES (?, ?, ?, ?, ?)"
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        
        cursor.execute(query, (now, calibration, cyl_num, exp_date_input, concentration_input))
        conn.commit()
        
        print(f"\n✅ SUCCESS: Record added to {target_table}")
        input("\nUpdate complete. Press Enter to exit...")

    except Exception as e:
        exit_program(f"Database Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    update_cylinder()
