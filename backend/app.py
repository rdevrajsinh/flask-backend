import os
from flask import Flask, request, jsonify
from datetime import datetime
from dateutil import parser
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_session import Session
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS for your frontend app
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000", "supports_credentials": True}})
print(os.getenv("DATAB"))
# Configure session to store data in PostgreSQL
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = os.getenv("DATAB")  # Using the same DATABASE_URL for session storage
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATAB")  # Set the database URI for SQLAlchemy
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable Flask-SQLAlchemy modifications tracking
app.config['SESSION_PERMANENT'] = False  # Session lasts until the browser is closed
app.config['SESSION_COOKIE_NAME'] = 'my_session_cookie'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Set this in your .env file
Session(app)  # Initialize session management

# WHOIS API details
WHOIS_API_URL = os.getenv("WHOIS_API_URL")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# Database connection
def get_db_connection():
    conn = psycopg2.connect(os.getenv("DATAB"))
    return conn

# Get session data from the database
def get_session(session_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM sessions WHERE session_id = %s", (session_id,))
    session = cursor.fetchone()
    cursor.close()
    conn.close()
    return session

# Create necessary tables
def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(255) NOT NULL
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

def create_sessions_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            session_id VARCHAR(255) NOT NULL,
            username VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

def create_domains_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id SERIAL PRIMARY KEY,
            domain_name VARCHAR(255) NOT NULL,
            expiry_date DATE,
            created_date DATE,
            updated_date DATE,
            organization VARCHAR(255),
            server_name VARCHAR(255),
            custom_option VARCHAR(255),
            is_active BOOLEAN
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Route to check session (authentication)
@app.route('/api/check_session', methods=['GET'])
def check_session():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if session_id:
        session_data = get_session(session_id)  # Get session data from the database
        if session_data and 'username' in session_data:
            return jsonify({"message": f"User {session_data['username']} is authenticated"}), 200
    return jsonify({"error": "Unauthorized access"}), 403

# Route to get all domains (protected)
@app.route('/api/domains', methods=['GET'])
def get_all_domains():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not get_session(session_id):
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

# Route to add a new domain (protected)
@app.route('/api/domain', methods=['POST'])
def add_domain():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not get_session(session_id):
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

# Route to update custom option for domain (protected)
@app.route('/api/domain/<string:domain_name>', methods=['PUT'])
def update_custom_option_by_name(domain_name):
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not get_session(session_id):
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

# Route to delete domain (protected)
@app.route('/api/domain/<string:domain_name>', methods=['DELETE'])
def delete_domain(domain_name):
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not get_session(session_id):
        return jsonify({"error": "Unauthorized access, please login"}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

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
    create_sessions_table()
    create_domains_table()
    app.run(debug=True)
