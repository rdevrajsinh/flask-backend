from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import psycopg2
import os
import requests
from dateutil import parser
from datetime import datetime
import logging

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000", "supports_credentials": True}})

# Configure session
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Set this in your .env file
app.config['SESSION_COOKIE_NAME'] = 'my_session_cookie'
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Adjust as needed

WHOIS_API_URL = os.getenv("WHOIS_API_URL")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# Database connection setup
def get_db_connection():
    conn = psycopg2.connect(os.getenv("POSTGRES_URL"))  # Use Supabase Postgres URL
    return conn

# Create users table
def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Create domains table with custom_option
def create_domains_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domains (
        id SERIAL PRIMARY KEY,
        domain_name VARCHAR(255) UNIQUE NOT NULL,
        expiry_date TIMESTAMP,
        created_date TIMESTAMP,
        updated_date TIMESTAMP,
        organization VARCHAR(255),
        server_name TEXT[] ,
        custom_option VARCHAR(255),  -- New field for custom option
        is_active BOOLEAN,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    cursor.close()
    conn.close()

logging.basicConfig(level=logging.ERROR)

# Login user route
@app.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        # Check if the user exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = %s;", (username,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({"error": "User  not found"}), 404

        stored_password = user[1]
        if password == stored_password:
            session['username'] = username  # Store username in the session
            cursor.close()
            conn.close()
            return jsonify({"message": "Login successful", "username": username}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 400

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return jsonify({"error": "An internal error occurred, please try again later"}), 500

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"error": "Username already exists"}), 400

        # Insert new user into the users table
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING id;",
            (username, password)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({"message": "User  registered successfully", "user_id": user_id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Logout user route
@app.route('/api/logout', methods=['GET'])
def logout_user():
    session.pop('username', None)  # Remove username from the session
    return jsonify({"message": "Logged out successfully"}), 200

# Check session route for debugging
@app.route('/api/check_session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({"message": f"User  {session['username']} is authenticated"}), 200
    else:
        return jsonify({"error": "Unauthorized access"}), 403

# Protect domains route (only accessible if logged in)
@app.route('/api/domains', methods=['GET'])
def get_all_domains():
    if 'username' not in session:  # Check if user is authenticated
        return jsonify({"error": "Unauthorized access, please login"}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM domains;")
    domains = cursor.fetchall()

    domains_list = []
    for domain in domains:
        domains_list.append({
            'id': domain[0],
            'domain_name': domain[1],
            'expiry_date': domain[2],
            'created_date': domain[3],
            'updated_date': domain[4],
            'organization': domain[5],
            'server_name': domain[6],
            'custom_option': domain[9],
            'is_active': domain[8]
        })

    cursor.close()
    conn.close()
    return jsonify(domains_list)

# CRUD Operations for domains (add domain, update, delete)
@app.route('/api/domain', methods=['POST'])
def add_domain():
    if 'username' not in session:  # Check if user is authenticated
        return jsonify({"error": "Unauthorized access, please login"}), 403

    data = request.get_json()
    domain_name = data.get('domain_name')
    custom_option = data.get('custom_option') 

    if not domain_name or not custom_option:
        return jsonify({"error": "Domain name and custom option are required"}), 400

    try:
        response = requests.get(WHOIS_API_URL, params={
            "apiKey": WHOIS_API_KEY,
            "domainName": domain_name,
            "outputFormat": "JSON"
        })

        if response.status_code == 200:
            result = response.json()
            whois_record = result.get("WhoisRecord", {})
            expiry_date = whois_record.get("expiresDate")
            created_date = whois_record.get("createdDate")
            updated_date = whois_record.get("updatedDate")
            organization = whois_record.get("registrant", {}).get("organization", "N/A")
            name_servers = whois_record.get("nameServers", {}).get("hostNames", [])
            is_active = False

            if expiry_date:
                expiry_date_obj = parser.parse(expiry_date).date()
                today_date = datetime.utcnow().date()
                is_active = expiry_date_obj > today_date

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO domains (domain_name, expiry_date, created_date, updated_date, organization, server_name, custom_option, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """, (domain_name, expiry_date, created_date, updated_date, organization, name_servers, custom_option, is_active))
            domain_id = cursor.fetchone()[0]
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({"message": "Domain added successfully", "domain_id": domain_id}), 201
        else:
            return jsonify({"error": "Failed to fetch domain data from WHOIS API"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Other routes (update, delete, etc.) should also include the session check
@app.route('/api/domain/<string:domain_name>', methods=['PUT'])
def update_custom_option_by_name(domain_name):
    if 'username' not in session:  # Check if user is authenticated
        return jsonify({"error": "Unauthorized access, please login"}), 403

    data = request.get_json()
    custom_option = data.get('custom_option')

    if not custom_option:
        return jsonify({"error": "Custom option is required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        UPDATE domains
        SET custom_option = %s
        WHERE domain_name = %s;
        """, (custom_option, domain_name))
        
        if cursor.rowcount == 0:  # No rows were updated
            cursor.close()
            conn.close()
            return jsonify({"error": f"Domain '{domain_name}' not found"}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": f"Custom option for domain '{domain_name}' updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/domain/<string:domain_name>', methods=['DELETE'])
def delete_domain(domain_name):
    if 'username' not in session:  # Check if user is authenticated
        return jsonify({"error": "Unauthorized access, please login"}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete the domain with the specified domain_name
        cursor.execute("""
        DELETE FROM domains
        WHERE domain_name = %s;
        """, (domain_name,))

        if cursor.rowcount == 0:  # No rows were deleted
            cursor.close()
            conn.close()
            return jsonify({"error": f"Domain '{domain_name}' not found"}), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": f"Domain '{domain_name}' deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    create_users_table()
    create_domains_table()
    app.run(debug=True)
