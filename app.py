import os
import shutil
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, make_response
from functools import wraps
from dns import resolver
from io import BytesIO
import pdfkit
import dns.resolver
import logging
from lxml import etree
from datetime import datetime, timezone, timedelta
import pytz
import re
import gzip
import zipfile
from io import BytesIO
from azure.storage.blob import BlobServiceClient
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import requests
import json
import pyodbc
from dotenv import load_dotenv
import platform
from weasyprint import HTML

# Load environment variables from .env file (only required if running locally)
load_dotenv(override=True)

# Flask App Initialization
app = Flask(__name__)

# Secret key for session management
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=25)

@app.context_processor
def inject_request():
    return dict(request=request)


@app.before_request
def make_session_permanent():
    session.permanent = True
    session.modified = True
    if 'last_activity' in session:
        now = datetime.utcnow()  # Use UTC time to ensure offset-naive datetime
        last_activity = session['last_activity']
        if isinstance(last_activity, str):
            last_activity = datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
        if (now - last_activity).total_seconds() > app.config['PERMANENT_SESSION_LIFETIME'].total_seconds():
            session.clear()
            flash('Session timed out due to inactivity.', 'warning')
            return redirect(url_for('login'))
    session['last_activity'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')  # Store UTC time in session

print("\nENV VARIABLES AFTER FORCED .env LOADING:")
print("AZURE_SQL_CONNECTIONSTRING =", os.getenv("AZURE_SQL_CONNECTIONSTRING"))

def get_db_connection():
    """Establish connection to Azure SQL Database using environment variable"""
    # Retrieve the connection string and strip quotes
    connection_string = os.getenv("AZURE_SQL_CONNECTIONSTRING", "").replace('"{', '{').replace('}"', '}')
    print("\nFinal Connection String:", connection_string)
    if not connection_string:
        print("Error: AZURE_SQL_CONNECTIONSTRING environment variable not set.")
        return None

    print("Using Connection String:", connection_string)

    # Modify connection string if needed (keeping Encrypt=yes for security)
    connection_string = connection_string.replace("TrustServerCertificate=no", "TrustServerCertificate=yes")

    try:
        print("Attempting database connection...")
        conn = pyodbc.connect(connection_string)
        print("Database connection successful!")
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def is_password_secure(password):
    """Ensure password contains at least 8 characters, 1 uppercase, 1 number, and 1 special character."""
    pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return bool(re.match(pattern, password))

# 🔍 Extract DMARC policy (quarantine/reject/none)
def get_dmarc_policy(record):
    match = re.search(r"\bp=([a-zA-Z]+)", record, re.IGNORECASE)
    return match.group(1).lower() if match else None

# 🚀 Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email_signup')
        password = request.form.get('password')

        # ✅ Password validation
        if not is_password_secure(password):
            flash("Password must contain at least 8 characters, 1 uppercase, 1 number, and 1 special character.", "danger")
            return render_template('signup.html')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        domain = email.split('@')[-1]

        db = get_db_connection()
        if db is None:
            flash("Database connection failed!", "danger")
            return redirect('/signup')

        try:
            cursor = db.cursor()

            # Insert user and get user_id
            cursor.execute("""
                INSERT INTO users (first_name, last_name, email, password, is_approved)
                OUTPUT INSERTED.user_id
                VALUES (?, ?, ?, ?, ?)
            """, (first_name, last_name, email, hashed_password, False))
            user_id = cursor.fetchone()[0]

            # Check or insert domain
            cursor.execute("SELECT domain_id FROM domains WHERE domain_name = ?", (domain,))
            domain_row = cursor.fetchone()

            if domain_row:
                domain_id = domain_row[0]
            else:
                cursor.execute("""
                    INSERT INTO domains (user_id, domain_name)
                    OUTPUT INSERTED.domain_id
                    VALUES (?, ?)
                """, (user_id, domain))
                domain_id = cursor.fetchone()[0]

            db.commit()
            cursor.close()
            db.close()

            flash("Registration successful. Waiting for approval.", "success")
            return redirect('/login')

        except Exception as e:
            db.rollback()
            print(f"❌ Error during signup: {e}")
            flash("Something went wrong. Please try again.", "danger")
            return render_template('signup.html')

    return render_template('signup.html', show_navbar=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        email = request.form.get("email_login")  # Updated key
        password = request.form.get("password_login")  # Updated key

        if not email or not password:
            flash("Email and password are required!", "danger")
            return render_template("login.html")

        db = get_db_connection()
        if db is None:
            flash("Database connection failed. Please try again later.", "danger")
            return render_template("login.html")

        try:
            cursor = db.cursor()
            cursor.execute("SELECT user_id, password, is_approved FROM users WHERE email=?", (email,))
            user = cursor.fetchone()
            cursor.close()
            db.close()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
                if not user[2]:  # Check if the user is approved
                    flash("Account pending approval.", "danger")
                    return render_template("login.html")
                session["user_id"] = user[0]
                session["email"] = email
                session['last_activity'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                return redirect("/dashboard")

            flash("Invalid email or password", "danger")
        except Exception as e:
            print(f"Error during login: {e}")
            flash("An error occurred while processing your request. Please try again.", "danger")

    return render_template("login.html", show_navbar=True)

# Admin route to approve users
@app.route('/admin/users')
@login_required
def admin_users():
    if session.get('email') != "admin@modaexperts.com":
        flash("Only admin users can access this page.", "danger")
        return redirect(url_for('dashboard'))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT user_id, first_name, last_name, email, is_approved FROM users ORDER BY user_id DESC")
    users = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/approve', methods=['POST'])
@login_required
def approve_user(user_id):
    if session.get('email') != "admin@modaexperts.com":
        flash("Only admin users can access this page.", "danger")
        return redirect(url_for('dashboard'))

    approve = request.form.get('approve', 'false').lower() == 'true'

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET is_approved = ? WHERE user_id = ?", (approve, user_id))
    db.commit()
    cursor.close()
    db.close()

    action = "approved" if approve else "rejected"
    flash(f"User successfully {action}.", "success")
    return redirect(url_for('admin_users'))

    
# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Get current date and time
current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Azure Blob Storage configuration
AZURE_CONNECTION_STRING = os.getenv('AZURE_CONNECTION_STRING')
if not AZURE_CONNECTION_STRING:
    raise ValueError("AZURE_CONNECTION_STRING environment variable not set.")

CONTAINER_NAME = 'xmlzipfiles'
blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)

# Function to convert epoch time to a readable date format
def epoch_to_date(epoch_time):
    return datetime.fromtimestamp(int(epoch_time)).strftime("%Y-%m-%d")

def epoch_to_est(epoch_time):
    est_timezone = pytz.timezone('America/New_York')
    return datetime.fromtimestamp(int(epoch_time), timezone.utc).astimezone(est_timezone).strftime("%Y-%m-%d %H:%M:%S %Z")

def date_string_to_epoch(date_string):
    est_timezone = pytz.timezone('America/New_York')
    try:
        # First, try parsing with full date, time, and timezone
        dt = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S %Z")
    except ValueError:
        try:
            # If that fails, try parsing with just the date and add timezone
            dt = datetime.strptime(date_string, "%Y-%m-%d")
            dt = est_timezone.localize(dt)  # Localize to EST timezone
        except ValueError:
            # If that fails too, try removing extra characters like timezone or time components
            cleaned_date_string = date_string.split(" ")[0]  # Only keep the date part
            dt = datetime.strptime(cleaned_date_string, "%Y-%m-%d")
            dt = est_timezone.localize(dt)  # Localize to EST timezone
    return int(dt.timestamp())

from datetime import datetime, timezone
import pytz

def est_to_epoch(est_date_str):
    # Expecting the input date in the format 'YYYY-MM-DD'
    est_datetime = datetime.strptime(est_date_str, "%Y-%m-%d")
    est_timezone = pytz.timezone('America/New_York')
    est_datetime = est_timezone.localize(est_datetime)
    epoch_time = int(est_datetime.timestamp())
    print(f"[DEBUG] Converted EST date '{est_date_str}' to epoch '{epoch_time}'")
    return epoch_time


# Function to parse the DMARC XML file
def parse_dmarc_xml(file_obj):
    try:
        tree = etree.parse(file_obj)
        aggregated_data = {"source_ips": []}
        
        # Extract organization name
        reporting_org = tree.findtext('.//report_metadata/org_name')
        aggregated_data["reporting_org"] = reporting_org if reporting_org else "Unknown Organization"
        
        # Parse date range and convert to EST
        begin_epoch = int(tree.findtext('.//date_range/begin'))
        end_epoch = int(tree.findtext('.//date_range/end'))
        begin_gmt = datetime.fromtimestamp(begin_epoch, timezone.utc)
        end_gmt = datetime.fromtimestamp(end_epoch, timezone.utc)

        est_timezone = pytz.timezone('America/New_York')
        begin_est = begin_gmt.astimezone(est_timezone)
        end_est = end_gmt.astimezone(est_timezone)

        aggregated_data["date_range"] = {
            "begin_gmt": begin_gmt.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "end_gmt": end_gmt.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "begin": begin_est.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "end": end_est.strftime("%Y-%m-%d %H:%M:%S %Z")
        }

        # Extract source IP data from each record
        for record in tree.xpath('//record'):
            source_ip_data = {
                "source_ip": record.findtext('row/source_ip'),
                "disposition": record.findtext('row/policy_evaluated/disposition'),
                "dkim_aligned": record.findtext('row/policy_evaluated/dkim'),
                "spf_aligned": record.findtext('row/policy_evaluated/spf'),
                "spf_domain": record.findtext('auth_results/spf/domain'),
                "spf_scope": record.findtext('auth_results/spf/scope'),
                "spf_authenticated": record.findtext('auth_results/spf/result'),
                "dkim_domain": record.findtext('auth_results/dkim/domain'),
                "dkim_selector": record.findtext('auth_results/dkim/selector'),
                "dkim_authenticated": record.findtext('auth_results/dkim/result'),
            }
            aggregated_data["source_ips"].append(source_ip_data)

        print(f"[DEBUG] Parsed data: {aggregated_data}")

        return aggregated_data
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        print(f"[ERROR] Error parsing XML file: {e}")
        return None

# Extract date range from XML file content, handling both ZIP and GZ formats
def extract_date_range(blob_name):
    blob_client = blob_service_client.get_container_client(CONTAINER_NAME).get_blob_client(blob_name)
    file_data = blob_client.download_blob().readall()

    # Check file type by extension
    if (blob_name.endswith('.zip')):
        # Handle ZIP files
        with zipfile.ZipFile(BytesIO(file_data)) as zip_file:
            for file_name in zip_file.namelist():
                if (file_name.endswith('.xml')):
                    with zip_file.open(file_name) as xml_file:
                        tree = etree.parse(xml_file)
                        begin_epoch = int(tree.findtext('.//date_range/begin'))
                        end_epoch = int(tree.findtext('.//date_range/end'))
                        begin_date = epoch_to_date(begin_epoch)
                        end_date = epoch_to_date(end_epoch)
                        return begin_date, end_date

    elif (blob_name.endswith('.gz')):
        # Handle GZ files
        with gzip.GzipFile(fileobj=BytesIO(file_data)) as gz_file:
            tree = etree.parse(gz_file)
            begin_epoch = int(tree.findtext('.//date_range/begin'))
            end_epoch = int(tree.findtext('.//date_range/end'))
            begin_date = epoch_to_date(begin_epoch)
            end_date = epoch_to_date(end_epoch)
            return begin_date, end_date

    # Return None if the file is neither .zip nor .gz or if an error occurs
    return None, None

# Function to fetch blobs with date ranges and filter by domain
def fetch_blobs_with_date_ranges(domain_filter=None):
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    blobs_with_dates = []
    for blob in container_client.list_blobs():
        if (blob.name.endswith('.zip') or blob.name.endswith('.gz')):
            begin_date, end_date = extract_date_range(blob.name)
            if (begin_date and end_date):
                # Convert begin_date and end_date to EST format for display
                begin_time_est = epoch_to_est(date_string_to_epoch(begin_date))
                end_time_est = epoch_to_est(date_string_to_epoch(end_date))
                domain = blob.name.split('!')[1]  # Extracting the domain
                # Filter based on domain if domain_filter is provided
                if (domain_filter is None or domain_filter in domain):
                    blobs_with_dates.append({
                        "name": blob.name,
                        "domain": domain,
                        "begin_time_est": begin_time_est,
                        "end_time_est": end_time_est
                    })
    return blobs_with_dates

# #old aggregate reports route
# @app.route('/aggregate_reports')
# def aggregate_reports():
#     # Get domain from query parameters for filtering
#     domain_filter = request.args.get('domain', None)
#     all_blobs = fetch_blobs_with_date_ranges(domain_filter)  # Pass domain_filter to function

#     return render_template('aggregate_reports.html', blobs=all_blobs, all_blobs=all_blobs)

# #old filter_reports route
# @app.route('/filter_reports', methods=['POST'])
# def filter_reports():
#     start_date = request.form.get('start_date')
#     end_date = request.form.get('end_date')
#     start_epoch = date_string_to_epoch(start_date)
#     end_epoch = date_string_to_epoch(end_date)

#     # Filter using EST dates
#     all_blobs = fetch_blobs_with_date_ranges()
#     filtered_blobs = [
#         blob for blob in all_blobs
#         if (date_string_to_epoch(blob['begin_time_est']) >= start_epoch and
#            date_string_to_epoch(blob['end_time_est']) <= end_epoch)
#     ]
#     return render_template('aggregate_reports.html', blobs=filtered_blobs, all_blobs=all_blobs)

#new aggregate report and filter_reports routes

@app.route('/aggregate_reports')
def aggregate_reports():
    # Get filter parameters
    domain_filter = request.args.get('domain', '').strip()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = int(request.args.get('page', 1))
    per_page = 10

    # Fetch all blobs with date range parsing
    all_blobs = fetch_blobs_with_date_ranges()

    # Apply domain filter
    if domain_filter:
        all_blobs = [blob for blob in all_blobs if domain_filter.lower() in blob['domain'].lower()]

    # Apply date filter if present
    if start_date and end_date:
        start_epoch = date_string_to_epoch(start_date)
        end_epoch = date_string_to_epoch(end_date)
        all_blobs = [blob for blob in all_blobs if (
            date_string_to_epoch(blob['begin_time_est']) >= start_epoch and
            date_string_to_epoch(blob['end_time_est']) <= end_epoch
        )]

    # Sort blobs by most recent first
    all_blobs.sort(key=lambda x: date_string_to_epoch(x['begin_time_est']), reverse=True)

    # Pagination
    total_items = len(all_blobs)
    total_pages = (total_items + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    paginated_blobs = all_blobs[start:end]

    return render_template(
        'aggregate_reports.html',
        show_navbar=True,
        blobs=paginated_blobs,
        total_pages=total_pages,
        page=page,
        request=request 
    )


@app.route('/view_report/<path:blob_name>')
def view_report(blob_name):
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    blob_client = container_client.get_blob_client(blob_name)
    
    # Check if it's a .zip file or .gz file and handle accordingly
    if (blob_name.endswith('.zip')):
        zip_data = blob_client.download_blob().readall()
        with zipfile.ZipFile(BytesIO(zip_data)) as zip_file:
            for file_name in zip_file.namelist():
                if (file_name.endswith('.xml')):
                    with zip_file.open(file_name) as xml_file:
                        data = parse_dmarc_xml(xml_file)
                        return render_template(
                            'results.html',
                            data=[data],
                            domain="modaexperts.com",
                            current_datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            dmarc_report=True
                        )
    
    elif (blob_name.endswith('.gz')):
        # Handle .gz file extraction (similar to .zip file)
        gz_data = blob_client.download_blob().readall()
        with gzip.GzipFile(fileobj=BytesIO(gz_data)) as gz_file:
            data = parse_dmarc_xml(gz_file)
            return render_template(
                'results.html',
                data=[data],
                domain="modaexperts.com",
                current_datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                dmarc_report=True
            )
    
    return "Invalid file type."




# Old Dashboard Route
# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('index.html', show_navbar=True)


#new dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    domain = session.get('email', '').split("@")[1]if 'email' in session else ''  # Extracting the Domain

    # Connect to the database
    db = get_db_connection()
    if db is None:
        flash("Database connection failed!", "danger")
        return redirect(url_for('login'))

    try:
        cursor = db.cursor()
        # Check if the domain exists in the dmarc_info table
        cursor.execute("SELECT dmarc_aligned, dmarc_configured FROM dmarc_info WHERE domain_name = ?", (domain,))
        domain_info = cursor.fetchone()
        cursor.close()
        db.close()

        if domain_info:
            dmarc_aligned, dmarc_configured = domain_info
            if dmarc_aligned == "yes" and dmarc_configured == "yes":
                render_button = True
            else:
                render_button= False
        else:
            render_button=False

    except Exception as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for('login'))

    return render_template('index.html', show_navbar=True, render_button=render_button)


# Default Route
@app.route('/')
def default():
    return redirect(url_for('login'))

@app.route('/logout-confirm')
def logout_confirm():
    return render_template('logout.html')

# Route for logout
@app.route("/logout", methods=["POST"])
def logout():
    """Clear session and log out the user."""
    session.clear()
    # flash("You have been logged out!", "success")
    return redirect("/login")


@app.route('/db-check')
def db_check():
    try:
        db = get_db_connection()  # Establish DB connection
        cursor = db.cursor(dictionary=True)  # Create a cursor
        cursor.execute("SELECT DATABASE();")
        db_name = cursor.fetchone()  # Fetch the database name
        cursor.close()
        db.close()  # Close connection
        return f"Connected to database: {db_name['DATABASE()']}"
    except mysql.connector.Error as err:
        return f"Error: {err}"




# Route to handle the DMARC report upload based on EST date
@app.route('/dmarc-report', methods=['GET', 'POST'])
def report():
    if (request.method == 'POST'):
        start_date = request.form.get('start_date')
        
        # Convert start date to epoch time at midnight UTC (assuming input is in "MM-DD-YYYY" format)
        try:
            # Parse start_date as a UTC datetime object at midnight
            start_date_obj = datetime.strptime(start_date, "%m-%d-%Y")
            start_date_utc = datetime(start_date_obj.year, start_date_obj.month, start_date_obj.day, 0, 0, 0, tzinfo=timezone.utc)
            start_epoch = int(start_date_utc.timestamp())
            print(f"Converted start date {start_date} to epoch time (UTC at midnight): {start_epoch}")
        except ValueError:
            return "Invalid date format. Please enter the date in MM-DD-YYYY format."

        # Define the directory where files are located
        uploads_folder = 'uploads'
        os.makedirs(uploads_folder, exist_ok=True)
        
        # Debug: Print the list of files in the directory
        all_files = os.listdir(uploads_folder)
        print("Files in uploads folder:", all_files)
        
        # Search for file with the exact start epoch time in its name
        file_name = next(
            (f for f in all_files if str(start_epoch) in f),
            None
        )

        if (not file_name):
            return f"No file found with start date {start_date} (epoch: {start_epoch})"

        file_path = os.path.join(uploads_folder, file_name)
        
        # Handle .gz and .zip files
        if (file_name.lower().endswith('.xml')):
            extracted_file_path = file_path  # Use XML directly

        elif (file_name.lower().endswith('.zip')):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                xml_files = [name for name in zip_ref.namelist() if name.endswith('.xml')]
                if (xml_files):
                    extracted_file_path = os.path.join(uploads_folder, xml_files[0])
                    zip_ref.extract(xml_files[0], uploads_folder)
                else:
                    return 'No XML file found in the ZIP archive.'

        elif (file_name.lower().endswith('.gz')):
            extracted_file_path = os.path.splitext(file_path)[0] + '.xml'
            with gzip.open(file_path, 'rb') as gz_file:
                with open(extracted_file_path, 'wb') as extracted_file:
                    shutil.copyfileobj(gz_file, extracted_file)

        else:
            return 'Invalid file format. Please upload an .xml, .zip, or .gz file.'

        # Parse the extracted XML file (implementation of parse_dmarc_xml function not shown here)
        aggregated_data = parse_dmarc_xml(extracted_file_path)
        os.remove(extracted_file_path)  # Clean up extracted XML file if it was decompressed

        if (aggregated_data):
            current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return render_template('results.html', data=aggregated_data, domain="modaexperts.com", current_datetime=current_datetime, dmarc_report=True)
        else:
            return 'No DMARC report data found in the .xml file or parsing error.'

    return render_template('index.html')


def get_dns_hosting_provider(domain):
    try:
        dns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [ns.target.to_text() for ns in dns_records]

        if (any('domaincontrol.com' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'GoDaddy'"
        elif (any('cloudflare.com' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Cloudflare'"
        elif (any('dnsmadeeasy.com' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'dnsmadeeasy'"     
        elif (any('att' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'AT&T'"    
        elif (any('google' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Google'"
        elif (any('googledomains' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Google'"       
        elif (any('amazonaws.com' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Amazon'"
        elif (any('awsdns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Amazon'"
        elif (any('opendns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'OpenDNS - Cisco Umbrella'"
        elif (any('openns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'OpenDNS - Cisco Umbrella'"  
        elif (any('azure-dns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Azure DNS'"
        elif (any('ns1.com' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'IBM NS1'"
        elif (any('nsone' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'NS1'"
        elif (any('ns4' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'ns4'"
        elif (any('akam.net' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Akamai Technologies'"
        elif (any('ultradns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Neustar UltraDNS'"
        elif (any('cloudns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'ClouDNS'"
        elif (any('dynect' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Dyn - Oracle Cloud Infrastructure'"
        elif (any('easydns' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'EasyDNS'"
        elif (any('registrar-servers' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Namecheap'"
        elif (any('bluehost' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'Bluehost'"
        elif (any('dreamhost' in ns for ns in nameservers)):
            return f"Your DNS hosting provider for {domain} is 'DreamHost'"
        else:
            return f"No recognized DNS hosting provider found for {domain}"
    except dns.resolver.NXDOMAIN:
        return None



# Function to fetch geolocation data for an IP
def get_ip_location(ip):
    try:
        # Use an API like ipapi or ipstack (replace 'YOUR_API_KEY' with an actual API key)
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if (response.status_code == 200):
            data = response.json()
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "isp": data.get("org"), 
            }
        else:
            return {"error": "Unable to fetch location"}
    except Exception as e:
        return {"error": str(e)}




def get_blocklist_status(ip_address):
    """
    Fetch blocklist status from AbuseIPDB for a given IP address.
    """
    try:
        api_key = "efdf9f1cf255cf5b34afc0f6a6fdbf6344dde83e6f2d2d3f4af8b7a936a056e0c74f656c4931010b"  # Replace with your actual API key
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for HTTP status codes >= 400
        data = response.json().get("data", {})

        return {
            "confidence": data.get("abuseConfidenceScore", "Unknown"),
            "reported_count": data.get("totalReports", "Unknown"),  # Fetch the total reports
            "isp": data.get("isp", "Unknown"),
            "usage_type": data.get("usageType", "Unknown"),
            "hostname": data.get("hostnames", []),
            "domain": data.get("domain", "Unknown"),
            "country": data.get("countryName", "Unknown"),
            "city": data.get("city", "Unknown"),
        }
    except requests.exceptions.HTTPError as http_err:
        return {"error": f"HTTP error occurred: {http_err}"}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"Request error occurred: {req_err}"}




#returns nameserver records 
def dns_hosting_provider(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        hosting_providers = [ns.target.to_text() for ns in ns_records]
        if (hosting_providers):
            return f"Name Server records for {domain}: {', '.join(hosting_providers)}"
        else:
            return None
    except dns.resolver.NXDOMAIN:
        return None

#returns mx records
def mx_lookup(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_results = [f"{mx.exchange} (Preference: {mx.preference})" for mx in mx_records]

    except dns.resolver.NXDOMAIN:
        mx_results = None
    return mx_results

#returns dmarc records
def dmarc_lookup(domain):
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_results = [f"{record}" for record in dmarc_records]

    except dns.resolver.NXDOMAIN:
        dmarc_results = None
    return dmarc_results

#returns dkim records
def dkim_lookup(domain):
    """
    Look up DKIM records for a given domain.
    """
    try:
        # Try to resolve the DKIM records
        dkim_records = dns.resolver.resolve(f'selector1._domainkey.{domain}', 'TXT')
        return [record.to_text() for record in dkim_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []  # Return an empty list instead of None
    except Exception as e:
        return [f"An error occurred: {e}"]

#returns spf records
def spf_lookup(domain):
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        spf_results = [record.strings[0].decode('utf-8') for record in spf_records if (record.strings and record.strings[0].startswith(b"v=spf1"))]
    except dns.resolver.NXDOMAIN:
        spf_results = None
    return spf_results

def dns_lookup(domain):
    try:
        dns_records = dns.resolver.resolve(domain, 'A')
        dns_results = [f"{record}" for record in dns_records]

    except dns.resolver.NoAnswer:
        # If no A record, try looking up a CNAME record
        try:
            cname_record = dns.resolver.resolve(domain, 'CNAME')
            dns_results = [f"CNAME found: {str(record)}" for record in cname_record]
        except dns.resolver.NoAnswer:
            # No A or CNAME record found
            dns_results = ["No A or CNAME record found for this domain."]
        except dns.exception.DNSException as e:
            # Handle other DNS-related errors
            return [f"Error retrieving CNAME record: {e}"]
        # return ["No A record found for this domain."]
    except dns.resolver.NXDOMAIN:
        dns_results = None   
    except dns.resolver.Timeout:
        return ["DNS query timed out."]
    except dns.exception.DNSException as e:
        return [f"Error retrieving DNS record: {e}"]
    return dns_results

# def mta_sts_lookup(domain):
#     try:
#         mta_sts_records = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
#         mta_sts_results = [record.strings[0] for record in mta_sts_records]
#         return mta_sts_results
#     except dns.resolver.NXDOMAIN:
#         return None

#returns MTA record
def mta_sts_lookup(domain):
    """
    Look up MTA-STS records for a given domain.
    """
    try:
        mta_sts_records = dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        return [record.to_text() for record in mta_sts_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []  # Return an empty list instead of None
    except Exception as e:
        return [f"An error occurred: {e}"]

    
#returns txt record
def txt_lookup(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        txt_results = [f"{record}" for record in txt_records]
    except dns.resolver.NXDOMAIN:
        txt_results = None
    return txt_results

def get_wkhtmltopdf_path():
    if (os.getenv("WEBSITE_HOSTNAME")):  # If running on Azure Web Apps
        return "/home/site/wwwroot/wkhtmltopdf"
    else:  # Local development path
        return "C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe"

#PDF generation
@app.route('/generate-pdf', methods=['POST'])
@login_required
def generate_pdf():
    print(f"🔍 Received request with method: {request.method}")
    print(f"🔍 Request Headers: {request.headers}")
    print(f"🔍 Request Form Data: {request.form}")
    if (request.method != 'POST'):
        return "Method Not Allowed", 405  # Explicitly return 405 for non-POST requests

    domain = request.form.get('domain', 'unknown')
    print(f"✅ Received domain: {domain}")
    
    # Proceed with PDF generation...
    try:
        # Get data from the form
        domain = request.form.get('domain', 'unknown')
        mx_results = mx_lookup(domain)
        dmarc_results = dmarc_lookup(domain)
        dkim_results = dkim_lookup(domain)  
        spf_results = spf_lookup(domain)   
        dns_results = dns_lookup(domain)
        mta_sts_results = mta_sts_lookup(domain)
        txt_results = txt_lookup(domain)
        hosting_provider = dns_hosting_provider(domain)
        dns_provider = get_dns_hosting_provider(domain)

        domain = request.form.get('domain', '').strip()
        blocklist_status = []  # Initialize as an empty list
        resolved_ips = []  # To store resolved IP addresses

        try:
            # Resolve the domain to its IP addresses
            ip_addresses = resolver.resolve(domain, 'A')  # 'A' record for IPv4

            for ip in ip_addresses:
                ip = ip.to_text()  # Convert the IP address object to string
                resolved_ips.append(ip)  # Add to resolved IPs list
                try:
                    # Fetch blocklist status for each IP
                    status = get_blocklist_status(ip)
                    blocklist_status.append({"ip": ip, "status": status})
                except Exception as e:
                    blocklist_status.append({"ip": ip, "status": {"error": f"Error: {e}"}})
        except resolver.NXDOMAIN:
            flash(f"Domain '{domain}' does not exist.", "danger")
        except resolver.NoAnswer:
            flash(f"No A record found for the domain '{domain}'.", "danger")
        except resolver.Timeout:
            flash(f"DNS resolution for the domain '{domain}' timed out.", "danger")
        except Exception as e:
            flash(f"An error occurred while resolving IP addresses for '{domain}': {e}", "danger")

        # Get location for the first IP in DNS results
        ip_location = {}
        if (dns_results and isinstance(dns_results, list)):
            ip_location = get_ip_location(dns_results[0].strip())
    
        # Render the HTML template with the data
        html = render_template(
            'PDF_Generation.html',
            domain=domain,
            dns_provider=dns_provider,
            hosting_provider=hosting_provider,
            txt_results=txt_results,
            mta_sts_results=mta_sts_results,
            mx_results=mx_results,
            dmarc_results=dmarc_results,
            dkim_results=dkim_results,
            spf_results=spf_results,
            dns_results=dns_results,
            blocklist_status=blocklist_status, 
            ip_location=ip_location,
            current_datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            email_security=True
        )
        
        # Generate PDF using WeasyPrint
        pdf = HTML(string=html).write_pdf()

        # Create the response
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=email_security_report_{domain}_{datetime.now().strftime("%Y%m%d")}.pdf'

        return response

    except Exception as e:
        print(f"Error generating PDF: {e}")
        flash("Error generating PDF report.", "error")
        return redirect(url_for('results'))

#dns.resolver.resolve(f'selector1._domainkey.{domain}', 'TXT')



def is_valid_dkim_record(domain, selector="selector1", record_type="TXT"):
    dkim_name = f"{selector}._domainkey.{domain}"
    try:
        print(f"🔍 Checking DKIM record: {dkim_name}")
        records = dns.resolver.resolve(dkim_name, record_type)
        for record in records:
            if "v=DKIM1" in record.to_text():
                print(f"✅ Valid DKIM record found: {dkim_name}")
                return True
        print(f"❌ DKIM record exists but is not valid: {dkim_name}")
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout) as e:
        print(f"❌ DKIM record does not exist: {dkim_name} - Error: {e}")
        return False


def has_valid_dkim(domain):
    selectors = ["default", "selector1", "google", "mail", "email", "d365"]
    for selector in selectors:
        if is_valid_dkim_record(domain, selector):
            return True
    print(f"❌ No valid DKIM record found for any known selectors for domain: {domain}")
    return False


def is_valid_mta_sts_record(name):
    try:
        records = dns.resolver.resolve(name, "TXT")
        for record in records:
            if "v=STSv1" in record.to_text():
                print(f"✅ Valid MTA-STS record found: {name}")
                return True
        print(f"❌ No valid MTA-STS record found: {name}")
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
        print(f"❌ MTA-STS record does not exist: {name}")
        return False


def dns_record_exists(name, record_type="TXT"):
    try:
        print(f"🔍 Checking DNS record: {name} ({record_type})")
        dns.resolver.resolve(name, record_type)
        print(f"✅ DNS record exists: {name} ({record_type})")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout) as e:
        print(f"❌ DNS record does not exist: {name} ({record_type}) - Error: {e}")
        return False


def check_dmarc_aligned(domain):
    dmarc_present = dns_record_exists(f"_dmarc.{domain}", "TXT")
    dkim_configured = has_valid_dkim(domain)
    mta_sts_txt = dns_record_exists(f"_mta-sts.{domain}", "TXT")
    mta_sts_policy = dns_record_exists(f"mta-sts.{domain}", "A")

    print(f"✅ DMARC Presence: {dmarc_present}")
    print(f"✅ DKIM Presence: {dkim_configured}")
    print(f"✅ MTA-STS TXT Presence: {mta_sts_txt}")
    print(f"✅ MTA-STS A record Presence: {mta_sts_policy}")

    if dmarc_present and (dkim_configured or (mta_sts_txt and mta_sts_policy)):
        print(f"✅ Alignment: DMARC + {'DKIM' if dkim_configured else 'MTA-STS'}")
        return "yes"

    print("❌ Alignment: Incomplete - requires DMARC + (DKIM or MTA-STS)")
    return "no"


@app.route('/emailsecurity-results', methods=['POST'], endpoint='emailsecurity_results_handler')
@login_required
def emailsecurity_results():
    domain = request.form.get('domain', '').strip()

    mx_results = mx_lookup(domain)
    dmarc_results = dmarc_lookup(domain)
    dkim_results = dkim_lookup(domain)
    spf_results = spf_lookup(domain)
    dns_results = dns_lookup(domain)
    mta_sts_results = mta_sts_lookup(domain)
    txt_results = txt_lookup(domain)
    hosting_provider = dns_hosting_provider(domain)
    dns_provider = get_dns_hosting_provider(domain)

    blocklist_status = []
    resolved_ips = []

    try:
        ip_addresses = dns.resolver.resolve(domain, 'A')
        for ip in ip_addresses:
            ip = ip.to_text()
            resolved_ips.append(ip)
            try:
                status = get_blocklist_status(ip)
                blocklist_status.append({"ip": ip, "status": status})
            except Exception as e:
                blocklist_status.append({"ip": ip, "status": {"error": f"Error: {e}"}})
    except dns.resolver.NXDOMAIN:
        flash(f"Domain '{domain}' does not exist.", "danger")
    except dns.resolver.NoAnswer:
        flash(f"No A record found for the domain '{domain}'.", "danger")
    except dns.resolver.Timeout:
        flash(f"DNS resolution for the domain '{domain}' timed out.", "danger")
    except Exception as e:
        flash(f"An error occurred while resolving IP addresses for '{domain}': {e}", "danger")

    ip_location = {}
    if dns_results and isinstance(dns_results, list):
        ip_location = get_ip_location(dns_results[0].strip())

    dmarc_aligned = check_dmarc_aligned(domain)

    return render_template(
        'results.html',
        domain=domain,
        dns_provider=dns_provider,
        hosting_provider=hosting_provider,
        txt_results=txt_results,
        mta_sts_results=mta_sts_results,
        mx_results=mx_results,
        dmarc_results=dmarc_results,
        dkim_results=dkim_results,
        spf_results=spf_results,
        dns_results=dns_results,
        blocklist_status=blocklist_status,
        ip_location=ip_location,
        dmarc_aligned=dmarc_aligned,
        current_datetime=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        email_security=True
    )



@app.route('/view-profile')
def view_profile():
    if ('user_id' not in session):
        flash("You need to log in to view your profile.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT first_name, last_name, email FROM users WHERE user_id=?", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    if (not user):
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))

    # Manually convert the result to a dictionary
    user_dict = {
        'first_name': user[0],
        'last_name': user[1],
        'email': user[2]
    }

    return render_template('profile.html', user=user_dict, show_navbar=True)

@app.route('/add_domain', methods=['GET', 'POST'])
@login_required
def add_domain():
    if request.method == 'POST':
        domain_name = request.form.get('domain_name')
        user_id = session['user_id']

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("INSERT INTO domains (user_id, domain_name) VALUES (?, ?)", (user_id, domain_name))
        db.commit()
        cursor.close()
        db.close()

        flash("Domain added successfully.", "success")
        return redirect(url_for('view_domains'))

    return render_template('add_domain.html')

@app.route('/view_domains')
@login_required
def view_domains():
    user_id = session['user_id']

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT user_id, domain_name, created_at, last_scanned_at, scan_status, report_path, is_active FROM domains WHERE user_id=?", (user_id,))
    domains = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template('view_domains.html', domains=domains)

import requests

@app.route('/website-scan', methods=['POST'])
@login_required
def website_scan():
    website = request.form.get('website')
    if not website:
        flash("Please enter a website to scan.", "danger")
        return redirect(url_for('dashboard'))

    # Burp Suite REST API configuration
    BURP_API_URL = "http://172.16.2.163:1337/v0.1/"  # Update with your Burp API URL
    BURP_API_KEY = "sZ2BIwMzQcZ9Nhr55CKZJwv2VUoRNmd0"  # Replace with your actual API key

    try:
        headers = {"Authorization": f"Bearer {BURP_API_KEY}"}
        # Add configuration type to the scan data
        scan_data = {
            "urls": [website],  # The target website
            "configuration": "audit-passive"  # Set the configuration type here
        }

        # Send the POST request to start the scan
        response = requests.post(f"{BURP_API_URL}/scan", json=scan_data, headers=headers)

        # Log the response for debugging
        print(f"Response status code: {response.status_code}")
        print(f"Response headers: {response.headers}")
        print(f"Response body: {response.text}")

        if response.status_code == 201:  # Scan created successfully
            # Extract the scan_id from the Location header
            location_header = response.headers.get("Location")
            if location_header:
                scan_id = location_header.split("/")[-1]  # Extract the last part of the URL
                flash(f"Scan started for website '{website}'. Scan ID: {scan_id}", "success")
                return redirect(url_for('scan_status', scan_id=scan_id))
            else:
                flash("Scan started, but no scan ID was returned in the response.", "warning")
        else:
            flash(f"Failed to start scan: {response.text}", "danger")

    except requests.exceptions.RequestException as e:
        flash(f"Error connecting to Burp Suite API: {str(e)}", "danger")

    return redirect(url_for('dashboard'))

@app.route('/scan-results/<int:scan_id>', methods=['GET'])
@login_required
def scan_results(scan_id):
    BURP_API_URL = "http://172.16.2.163:1337/v0.1/"
    BURP_API_KEY = "sZ2BIwMzQcZ9Nhr55CKZJwv2VUoRNmd0"  # Replace with your actual API key

    try:
        headers = {"Authorization": f"Bearer {BURP_API_KEY}"}
        response = requests.get(f"{BURP_API_URL}/scan/{scan_id}", headers=headers)

        if response.status_code == 200:
            scan_data = response.json()
            issues = scan_data.get("issue_events", [])
            if not issues:
                flash("No issues were found for this scan.", "info")
            return render_template('scan_results.html', scan_id=scan_id, issues=issues)
        
        elif response.status_code == 500:
            flash("An internal server error occurred while fetching scan results. Please check Burp Suite logs.", "danger")
        
        else:
            print(f"Failed to fetch scan results: {response.status_code} - {response.text}")
            flash(f"Failed to fetch scan results: {response.text}", "danger")

    except requests.exceptions.RequestException as e:
        flash(f"Error connecting to Burp Suite API: {str(e)}", "danger")
        print(f"Error: {e}")

    return redirect(url_for('dashboard'))


@app.route('/scan-status/<int:scan_id>', methods=['GET'])
@login_required
def scan_status(scan_id):
    BURP_API_URL = "http://172.16.2.163:1337/v0.1/"
    BURP_API_KEY = "sZ2BIwMzQcZ9Nhr55CKZJwv2VUoRNmd0"  # Replace with your actual API key

    try:
        headers = {"Authorization": f"Bearer {BURP_API_KEY}"}
        response = requests.get(f"{BURP_API_URL}/scan/{scan_id}", headers=headers)

        if response.status_code == 200:
            scan_data = response.json()
            # Add a default value for issue_counts if it doesn't exist
            if 'issue_counts' not in scan_data:
                scan_data['issue_counts'] = {'total': 'Not available yet'}
            print(f"Scan Status: {scan_data}")
            return render_template('scan_status.html', scan_data=scan_data)
        else:
            flash(f"Failed to fetch scan status: {response.text}", "danger")
            return redirect(url_for('dashboard'))

    except requests.exceptions.RequestException as e:
        flash(f"Error connecting to Burp Suite API: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)