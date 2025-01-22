import os
from flask import Flask, request, jsonify
from datetime import datetime
from dateutil import parser
import requests
from flask_session import Session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Enable CORS for your frontend app
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000", "supports_credentials": True}})

# Configure the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("POSTGRES_URL")  # Set the database URI for SQLAlchemy
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable Flask-SQLAlchemy modifications tracking
print("DATABASE_URL:", os.getenv("POSTGRES_URL"))
# Configure session to store data in PostgreSQL
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = os.getenv("POSTGRES_URL")  # Using the same DATABASE_URL for session storage
app.config['SESSION_PERMANENT'] = False  # Session lasts until the browser is closed
app.config['SESSION_COOKIE_NAME'] = 'my_session_cookie'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Set this in your .env file

# Initialize SQLAlchemy and Session
db = SQLAlchemy(app)
Session(app)  # Initialize session management

# WHOIS API details
WHOIS_API_URL = os.getenv("WHOIS_API_URL")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# Define your models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)

class SessionModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)
    created_date = db.Column(db.Date, nullable=True)
    updated_date = db.Column(db.Date, nullable=True)
    organization = db.Column(db.String(255), nullable=True)
    server_name = db.Column(db.String(255), nullable=True)
    custom_option = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False)

# Create necessary tables
@app.before_first_request
def create_tables():
    db.create_all()  # Create tables if they don't exist

# Route to check session (authentication)
@app.route('/api/check_session', methods=['GET'])
def check_session():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if session_id:
        session_data = SessionModel.query.filter_by(session_id=session_id).first()  # Get session data from the database
        if session_data and 'username' in session_data:
            return jsonify({"message": f"User  {session_data.username} is authenticated"}), 200
    return jsonify({"error": "Unauthorized access"}), 403

# Route to get all domains (protected)
@app.route('/api/domains', methods=['GET'])
def get_all_domains():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not SessionModel.query.filter_by(session_id=session_id).first():
        return jsonify({"error": "Unauthorized access, please login"}), 403

    domains = Domain.query.all()
    domains_list = []
    for domain in domains:
        domains_list.append({
            'id': domain.id,
            'domain_name': domain.domain_name,
            'expiry_date': domain.expiry_date,
            'created_date': domain.created_date,
            'updated_date': domain.updated_date,
            'organization': domain.organization,
            'server_name': domain.server_name,
            'custom_option': domain.custom_option,
            'is_active': domain.is_active
        })

    return jsonify(domains_list)

# Route to add a new domain (protected)
@app.route('/api/domain', methods=['POST'])
def add_domain():
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not SessionModel.query.filter_by(session_id=session_id).first():
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

            new_domain = Domain(
                domain_name=domain_name,
                expiry_date=expiry_date,
                created_date=created_date,
                updated_date=updated_date,
                organization=organization,
                server_name=name_servers,
                custom_option=custom_option,
                is_active=is_active
            )
            db.session.add(new_domain)
            db.session.commit()

            return jsonify({"message": "Domain added successfully", "domain_id": new_domain.id}), 201
        else:
            return jsonify({"error": "Failed to fetch domain data from WHOIS API"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to update custom option for domain (protected)
@app.route('/api/domain/<string:domain_name>', methods=['PUT'])
def update_custom_option_by_name(domain_name):
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not SessionModel.query.filter_by(session_id=session_id).first():
        return jsonify({"error": "Unauthorized access, please login"}), 403

    data = request.get_json()
    custom_option = data.get('custom_option')

    if not custom_option:
        return jsonify({"error": "Custom option is required"}), 400

    try:
        domain = Domain.query.filter_by(domain_name=domain_name).first()
        if not domain:
            return jsonify({"error": f"Domain '{domain_name}' not found"}), 404

        domain.custom_option = custom_option
        db.session.commit()

        return jsonify({"message": f"Custom option for domain '{domain_name}' updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to delete domain (protected)
@app.route('/api/domain/<string:domain_name>', methods=['DELETE'])
def delete_domain(domain_name):
    session_id = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
    if not session_id or not SessionModel.query.filter_by(session_id=session_id).first():
        return jsonify({"error": "Unauthorized access, please login"}), 403

    try:
        domain = Domain.query.filter_by(domain_name=domain_name).first()
        if not domain:
            return jsonify({"error": f"Domain '{domain_name}' not found"}), 404

        db.session.delete(domain)
        db.session.commit()

        return jsonify({"message": f"Domain '{domain_name}' deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
