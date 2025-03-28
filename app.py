"""FinServ: A Financial Services App for Borrowers and Investors"""

# Import necessary libraries
import sqlite3
import hashlib
import json
import datetime
import pandas as pd
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Determine layout dynamically
if "page" not in st.session_state:
    st.session_state["page"] = "login"  # Default to login

LAYOUT_MODE = "centered" if st.session_state["page"] in [
    "login", "register"] else "wide"

# Set Streamlit page layout to wide mode
st.set_page_config(
    page_title="FinServ: A Financial Services App",  # Title of the browser tab
    # Icon for the browser tab (Emoji or URL)
    page_icon="chart_with_upwards_trend",
    layout=LAYOUT_MODE,  # Layout type: "centered" or "wide"
    # Initial state of the sidebar: "auto", "expanded", or "collapsed"
    initial_sidebar_state="expanded"
)


# Initialize cookie manager
cookies = EncryptedCookieManager(
    prefix="finserv_ne3hckj923b3icn29", password="adminapp123")
if not cookies.ready():
    st.stop()


def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()

            # Create users table if it doesn't exist
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            amount_invested REAL
                            )''')

            # Create borrowers table if it doesn't exist
            cursor.execute('''CREATE TABLE IF NOT EXISTS borrowers (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                name TEXT UNIQUE NOT NULL,
                                mobile TEXT NOT NULL,
                                loan_amount REAL NOT NULL,
                                loan_tenure INTEGER NOT NULL,
                                start_date TEXT NOT NULL,
                                daily_collection REAL NOT NULL,
                                status TEXT NOT NULL,
                                remarks TEXT
                            )''')
            conn.commit()
    except sqlite3.Error as e:
        raise RuntimeError(f"Failed to set up database: {e}") from e


def register_user(username, password):
    """Register a new user by inserting username and hashed password into the database."""

    if not username or not password:
        raise ValueError("Username and password cannot be empty.")

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Hash the password
    hashed_password = hash_password(password)

    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Insert user data into the database
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (username, hashed_password))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        st.error("Username already exists.")
        return False
    except sqlite3.Error as e:
        sqlite3.error(f"Database error: {e}")
        return False


def login_user(username, password):
    """Authenticate a user and provide specific error messages for invalid login attempts."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        # Check if the username exists
        cursor.execute(
            "SELECT password, username FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

    if not user:
        return "Username does not exist."  # Username not found

    stored_password, username = user
    if stored_password != hash_password(password):
        return "Incorrect password."  # Password mismatch

    # Store user ID in cookies upon successful login
    cookies["user_name"] = str(username)
    cookies["logged_in"] = str(True)
    cookies.save()

    return True  # Successful login


def logout_user():
    """Log out the user by clearing the cookies."""
    cookies["user_name"] = ""
    cookies["logged_in"] = ""
    cookies.save()


def update_user_investment(username, amount):
    """Update the user's investment amount in the database."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET amount_invested=? WHERE username=?",
                   (amount, username))
    conn.commit()
    conn.close()


def get_users():
    """Fetch all users from the database."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    conn.commit()
    conn.close()
    return users


def add_borrower(borrower_data):
    """Add a new borrower to the database."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        # Check if borrower_data is a string and parse it as JSON
        if isinstance(borrower_data, str):
            try:
                borrower_data = json.loads(borrower_data)
            except json.JSONDecodeError as e:
                raise ValueError(
                    "Invalid JSON format for borrower data") from e
        elif not isinstance(borrower_data, dict):
            raise ValueError(
                "borrower_data must be a JSON string or a dictionary")
        # Ensure all required fields are present
        required_fields = ['name', 'mobile', 'loan_amount', 'loan_tenure',
                           'start_date', 'daily_collection', 'status']
        for field in required_fields:
            if field not in borrower_data:
                raise ValueError(f"Missing required field: {field}")

        # Insert borrower data into the database
        cursor.execute('''INSERT INTO borrowers (name, mobile, loan_amount, loan_tenure,
                    start_date, daily_collection, status, remarks) 
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (borrower_data['name'], borrower_data['mobile'], borrower_data['loan_amount'],
                        borrower_data['loan_tenure'], borrower_data['start_date'],
                        borrower_data['daily_collection'], borrower_data['status'], borrower_data['remarks']))

        conn.commit()


def update_remarks(borrower_id, remarks):
    """Update the remarks for a borrower in the database."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Update the borrower's remarks
        cursor.execute("UPDATE borrowers SET remarks=? WHERE id=?",
                       (remarks, borrower_id))
        conn.commit()


def update_daily_payment(borrower_id, payment_amount):
    """Update the last payment date (current date) and last 
    payment amount for a borrower in the database."""

    # Input validation
    if not isinstance(borrower_id, int) or borrower_id <= 0:
        raise ValueError("borrower_id must be a positive integer")
    if not isinstance(payment_amount, (int, float)) or payment_amount < 0:
        raise ValueError("payment_amount must be a non-negative number")

    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Update the borrower's record with the current timestamp and payment amount
            cursor.execute(
                '''UPDATE borrowers SET last_payment_date=CURRENT_TIMESTAMP,
                last_payment_amount=? WHERE id=?''',
                (payment_amount, borrower_id)
            )
            conn.commit()
            # Check if any rows were affected (i.e., borrower exists)
            if cursor.rowcount == 0:
                return False  # Borrower not found
            return True  # Update successful
    except sqlite3.Error as e:
        raise sqlite3.Error(f"Database error: {e}")


def close_loan(borrower_id):
    """Close a loan by updating its status in the database."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Update the borrower's status to 'Closed'
        cursor.execute(
            "UPDATE borrowers SET status='Closed' WHERE id=?", (borrower_id,))
        conn.commit()


def get_borrowers():
    """Fetch all borrowers from the database."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Fetch all borrowers
        cursor.execute("SELECT * FROM borrowers")
        borrowers = cursor.fetchall()

        conn.commit()
    return borrowers


def search_borrower(borrower):
    """Search for a borrower by name or mobile number."""
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Search for borrowers by name or mobile number
        cursor.execute(
            "SELECT * FROM borrowers WHERE name=? OR mobile=?", (borrower, borrower))
        borrowers = cursor.fetchall()
        conn.commit()
    return borrowers


def log_changes(changes):
    """Log changes to a file with timestamps."""
    # Ensure the log file is opened in append mode with UTF-8 encoding
    with open("changes_log.txt", "a", encoding="utf-8") as log_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for change in changes:
            log_file.write(f"{timestamp} - {change}\n")


def update_database(row_id, column, new_value):
    """Update a specific column in the database for a given row ID."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Update query (Modify for your database)
    query = f"UPDATE borrowers SET `{column}` = ? WHERE id = ?"
    cursor.execute(query, (new_value, row_id))

    conn.commit()
    conn.close()


def main():
    """Main function to run the Streamlit app."""

    init_db()

    if cookies.get("logged_in"):
        st.session_state["logged_in"] = True
        st.session_state["username"] = cookies.get("user_name")
        if not st.session_state.get('page') or st.session_state.get('page') is "login" or st.session_state.get('page') is "register":
            # Initialize session state for the page
            st.session_state['page'] = "view_borrowers"
    else:
        st.session_state["logged_in"] = False
        st.session_state["username"] = None
        if not st.session_state.get('page'):
            # Initialize session state for the page
            st.session_state['page'] = "login"

    if st.session_state['page'] == "login":
        st.title("Log In")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        # Create two columns for the buttons
        col1, col2 = st.columns([13, 2])
        with col1:
            if st.button("Log In", key="login_button"):
                result = login_user(username, password)
                if result is True:
                    st.success("Login successful!")
                    st.session_state['page'] = "view_borrowers"
                    st.rerun()
                elif result == "Username does not exist.":
                    st.error("Username does not exist. Please register.")
                else:
                    st.error("Incorrect password.")
        with col2:
            if st.button("Register", key="register_button"):
                st.session_state['page'] = "register"
                st.rerun()

    if st.session_state['page'] == "register":
        st.title("Register")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        # Create two columns for the buttons
        col1, col2 = st.columns([13, 2])
        with col1:
            if st.button("Register", key="register_button"):
                if register_user(username, password):
                    st.success("Registration successful!")
                    st.session_state['page'] = "login"
                    st.rerun()
        with col2:
            if st.button("Log In", key="login_button"):
                st.session_state['page'] = "login"
                st.rerun()

    if 'page_number' not in st.session_state:
        st.session_state['page_number'] = 1

    if st.session_state['page'] == "view_borrowers":
        st.title("FinServ: Financial Services App")
        col1, col2 = st.columns([13, 2])
        with col1:
            st.write("You are logged in as: " +
                     str(st.session_state["username"]))
        with col2:
            if st.sidebar.button("Log Out"):
                logout_user()
                st.session_state['page'] = "login"
                st.session_state["logged_in"] = False
                st.session_state["user_name"] = None
                st.rerun()
            if st.sidebar.button("Add Borrower"):
                st.session_state['page'] = "add_borrower"
                st.rerun()
            if st.sidebar.button("View Changes"):
                st.session_state['page'] = "view_changes"
                st.rerun()

        borrowers = get_borrowers()
        if not borrowers:
            st.write("No borrowers found.")
        else:
            # Display the borrowers in a table
            # Convert borrowers' data to a DataFrame
            columns = ["ID", "Name", "Mobile", "Loan Amount", "Loan Tenure", "Start Date",
                       "Daily Collection", "Status", "Remarks"]

            sql_columns = dict(zip(columns, ["id", "name", "mobile", "loan_amount", "loan_tenure",
                                             "start_date", "daily_collection", "status", "remarks"]))

            df = pd.DataFrame(borrowers, columns=columns).set_index("ID")
            for col in ["Loan Amount", "Loan Tenure", "Daily Collection"]:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype(int)

            # Search for a borrower
            search_query = st.text_input(
                "Search Borrowers by Name or Mobile or Status")

            if search_query:
                filtered_df = df[df.apply(
                    lambda row: search_query.lower() in str(row).lower(), axis=1)]

                if filtered_df.empty:
                    st.warning(
                        "No results found. Please try a different search term.")
                else:
                    df = filtered_df.copy()

            # Store original data in session state
            if "original_df" not in st.session_state:
                st.session_state.original_df = df.copy()

            # Display editable table
            edited_df = st.data_editor(
                df, use_container_width=True, key="editable_table")

            # Detect changes
            changes = (edited_df != st.session_state.original_df).stack()
            changed_cells = changes[changes].index.tolist()

            # Log changes & update database
            if changed_cells:
                log_entries = []
                # Get current user
                username = str(st.session_state["username"])

                for row, col in changed_cells:
                    old_value = st.session_state.original_df.at[row, col]
                    new_value = edited_df.at[row, col]

                    # Log the change
                    log_entries.append(
                        f"User: {username} | Row ID {row} - Column '{col}': '{old_value}' → '{new_value}'"
                    )

                    column = sql_columns[col]

                    # Update the database
                    update_database(row, column, new_value)

                # Save log to file
                log_changes(log_entries)

                # Update session state
                st.session_state.original_df = edited_df.copy()

            # Display the table in Streamlit
            # st.dataframe(df, use_container_width=True)
            # st.table(df)

    if st.session_state['page'] == "add_borrower":
        st.title("Add Borrower")
        borrower_data = {
            'name': st.text_input("Name"),
            'mobile': st.text_input("Mobile"),
            'loan_amount': st.number_input("Loan Amount", min_value=0, step=1000),
            'loan_tenure': st.number_input("Loan Tenure (in days)", min_value=100, step=10),
            'start_date': st.date_input("Start Date"),
            'daily_collection': st.number_input(
                "Daily Collection Amount", min_value=100, step=10),
            'status': 'ACTIVE',
            'remarks': st.text_area("Remarks")
        }

        if st.button("Add Borrower"):
            try:
                add_borrower(borrower_data)
                st.success("Borrower added successfully!")
                st.session_state['page'] = "view_borrowers"
                st.rerun()
            except ValueError as e:
                st.error(f"Error: {e}")

    if st.session_state['page'] == "view_changes":
        st.title("Changes made to Borrowers Database.")
        col1, col2 = st.columns([13, 2])
        with col1:
            st.write("You are logged in as: " +
                     str(st.session_state["username"]))
        with col2:
            if st.sidebar.button("Log Out"):
                logout_user()
                st.session_state['page'] = "login"
                st.session_state["logged_in"] = False
                st.session_state["user_name"] = None
                st.rerun()
            if st.sidebar.button("View Borrowers"):
                st.session_state['page'] = "view_borrowers"
                st.rerun()
        # Read the log file and display its contents
        try:
            with open("changes_log.txt", "r", encoding="utf-8") as log_file:
                changes = log_file.readlines()
            if changes:
                st.write("Changes made to the borrowers:")
                for change in changes:
                    st.write(change.strip())
            else:
                st.write("No changes logged yet.")
        except FileNotFoundError:
            st.write("No changes logged yet.")


if __name__ == "__main__":
    main()
