from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import logging
import os
import traceback
import re
from collections import defaultdict
from typing import Dict

from domain_whois import get_whois_info, save_whois_info_to_db, whois_recently_retrieved, init_db as init_db1
from subdomain_enumeration import domain_recently_scanned, init_db as init_db2, main as subdomain_enum
from globals import BASE_DIR, DB_FILE, is_second_level_domain
from web_status_header import main as web_header_analysis, init_db as init_db3
from ip_geolocation import init_geolocation_db, main as ip_geolocation_analysis

app = Flask(__name__)

# Configure CORS
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": "*"}})

@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'Domain parameter is required'}), 400

        domain = data['domain']

        if not is_second_level_domain(domain):
            return jsonify({'error': 'Invalid domain format'}), 400

        if whois_recently_retrieved(domain):
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM whois_info WHERE domain = ?", (domain,))
                whois_data = cursor.fetchone()
                if whois_data:
                    whois_dict = {
                        "id": whois_data[0],
                        "domain": whois_data[1],
                        "registrar": whois_data[2],
                        "creation_date": whois_data[3],
                        "expiration_date": whois_data[4],
                        "name_servers": whois_data[5],
                        "organization": whois_data[6],
                        "admin_contact": whois_data[7],
                        "raw_text": whois_data[8],
                        "timestamp": whois_data[9]
                    }
                    return jsonify(whois_dict), 200
                else:
                    return jsonify({'error': 'WHOIS information not found in database'}), 404

        whois_info = get_whois_info(domain)
        if whois_info:
            save_whois_info_to_db(domain, whois_info)
            return jsonify(whois_info), 200
        else:
            return jsonify({'error': 'WHOIS information not found'}), 404

    except Exception as e:
        logging.error(f"WHOIS lookup error: {e}")
        logging.error(traceback.format_exc())  # Logs the full traceback
        return jsonify({'error': 'An error occurred'}), 500
    

@app.route('/api/whois', methods=['GET'])
def get_all_whois():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM whois_info")
            whois_data = cursor.fetchone()
            if whois_data:
                whois_dict = {
                    "id": whois_data[0],
                    "domain": whois_data[1],
                    "registrar": whois_data[2],
                    "creation_date": whois_data[3],
                    "expiration_date": whois_data[4],
                    "name_servers": whois_data[5],
                    "organization": whois_data[6],
                    "admin_contact": whois_data[7],
                    "raw_text": whois_data[8],
                    "timestamp": whois_data[9]
                }
                return jsonify(whois_dict), 200
            else:
                return jsonify({'error': 'WHOIS information not found in database'}), 404

        whois_info = get_whois_info(domain)
        if whois_info:
            save_whois_info_to_db(domain, whois_info)
            return jsonify(whois_info), 200
        else:
            return jsonify({'error': 'WHOIS information not found'}), 404

    except Exception as e:
        logging.error(f"WHOIS lookup error: {e}")
        logging.error(traceback.format_exc())  # Logs the full traceback
        return jsonify({'error': 'An error occurred'}), 500


@app.route('/api/domain_enumeration', methods=['POST'])
def domain_enumeration():
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'Domain parameter is required'}), 400

        domain = data['domain']

        if domain_recently_scanned(domain):
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM subdomains WHERE domain = ?", (domain,))
                subdomains_data = cursor.fetchall()
                subdomains_list = [{
                    "id": subdomain[0],
                    "domain": subdomain[1],
                    "subdomain": subdomain[2],
                    "ip": subdomain[3],
                    "timestamp": subdomain[4]
                } for subdomain in subdomains_data]
            return jsonify(subdomains_list), 200

        subdomain_enum(domain)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM subdomains WHERE domain = ?", (domain,))
            subdomains_data = cursor.fetchall()
            subdomains_list = [{
                "id": subdomain[0],
                "domain": subdomain[1],
                "subdomain": subdomain[2],
                "ip": subdomain[3],
                "timestamp": subdomain[4]
            } for subdomain in subdomains_data]

        return jsonify(subdomains_list), 200

    except Exception as e:
        logging.error(f"Domain enumeration error: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': 'An error occurred'}), 500


@app.route('/api/domain_enumeration', methods=['GET'])
def get_domain_enumeration():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM subdomains")
            subdomains_data = cursor.fetchall()
            subdomains_list = [{
                "id": subdomain[0],
                "domain": subdomain[1],
                "subdomain": subdomain[2],
                "ip": subdomain[3],
                "timestamp": subdomain[4]
            } for subdomain in subdomains_data]

        return jsonify(subdomains_list), 200

    except Exception as e:
        logging.error(f"Domain enumeration error: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': 'An error occurred'}), 500


def parse_csp(csp_value: str) -> Dict[str, list]:
    """
    Parses the Content-Security-Policy header value and returns a structured dictionary
    separating the policy by source type (e.g., script-src, img-src, etc.).
    """
    # Define the source types to extract
    source_types = [
        'child-src', 'connect-src', 'default-src', 'font-src', 'form-action', 
        'frame-ancestors', 'frame-src', 'img-src', 'manifest-src', 'media-src', 
        'object-src', 'script-src', 'style-src', 'style-src-attr', 'worker-src'
    ]

    # Dictionary to store the CSP by source types
    csp_parsed = defaultdict(list)

    # Regular expression to match the source types and their values
    for source in source_types:
        # Look for the source type and its value(s) in the CSP string
        pattern = rf"({source})\s*['\"]?([^;]+)['\"]?"
        match = re.search(pattern, csp_value)
        
        if match:
            source_type = match.group(1)
            sources = match.group(2).split()
            csp_parsed[source_type].extend(sources)

    # Return the parsed CSP in a structured way
    return dict(csp_parsed)


@app.route('/api/security-headers', methods=['POST'])
def get_security_headers():
    """
    Retrieves security headers for a given domain from the database.
    If not found, it will fetch and analyze the headers.
    """
    try:
        # Parse JSON request body
        data = request.get_json()
        if not data or 'domain' not in data:
            logging.error("Missing 'domain' parameter in security headers request")
            return jsonify({"error": "Domain parameter is required"}), 400

        domain = data['domain'].strip()
        domain = f"https://{domain}"
        
        if not domain:
            return jsonify({"error": "Invalid domain"}), 400

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()

            # Fetch security headers from the database
            cursor.execute("""
                SELECT header_name, header_value, header_risk, header_description 
                FROM security_headers 
                WHERE url = ?
            """, (domain,))
            headers_data = cursor.fetchall()

            if not headers_data:
                # If headers are not found in the DB, fetch and analyze them
                web_header_analysis(domain)

                # Fetch again after analysis
                cursor.execute("""
                    SELECT header_name, header_value, header_risk, header_description 
                    FROM security_headers 
                    WHERE url = ?
                """, (domain,))
                headers_data = cursor.fetchall()

            if headers_data:
                headers_list = []
                for row in headers_data:
                    header_name = row[0]
                    header_value = row[1]
                    header_risk = row[2]
                    header_description = row[3]

                    # If the header is Content-Security-Policy, parse it into source types
                    if header_name == "Content-Security-Policy":
                        parsed_value = parse_csp(header_value)
                    else:
                        parsed_value = {"value": header_value}

                    headers_list.append({
                        "header_name": header_name,
                        "header_value": parsed_value,
                        "header_risk": header_risk,
                        "header_description": header_description
                    })
                return jsonify({"domain": domain, "security_headers": headers_list}), 200

        return jsonify({"error": "No security headers found"}), 404

    except Exception as e:
        logging.error(f"Error retrieving security headers for {domain}: {e}")
        logging.error(traceback.format_exc())  # Logs full traceback for debugging
        return jsonify({"error": "An internal error occurred"}), 500


@app.route('/api/geolocation', methods=['POST'])
def get_geolocation_data():
    """
    Retrieves the geolocation for a given domain by first resolving it to an IP address
    using nslookup and then fetching location data using a geolocation service.
    """
    try:
        # Parse JSON request body
        data = request.get_json()
        if not data or 'domain' not in data:
            logging.error("Missing 'domain' parameter in geolocation request")
            return jsonify({"error": "Domain parameter is required"}), 400

        domain = data['domain'].strip()
        
        if not domain:
            return jsonify({"error": "Invalid domain"}), 400

        # Connect to the database and check if geolocation data already exists
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ip_address, country, region, city, latitude, longitude, timestamp
                FROM ip_geolocation 
                WHERE domain = ?
            """, (domain,))
            geolocation_data = cursor.fetchone()



            if not geolocation_data:
                print("hello--------------")  # This is where the geolocation analysis starts
                ip_geolocation_analysis(domain)

                # Re-fetch the geolocation data after analysis has updated the database
                cursor.execute("""
                    SELECT ip_address, country, region, city, latitude, longitude, timestamp
                    FROM ip_geolocation 
                    WHERE domain = ?
                """, (domain,))
                geolocation_data = cursor.fetchone()

            ip_address = geolocation_data[0]
            geolocation_data = {
                "country": geolocation_data[1],
                "region": geolocation_data[2],
                "city": geolocation_data[3],
                "latitude": geolocation_data[4],
                "longitude": geolocation_data[5],
                "timestamp": geolocation_data[6]
            }
            logging.info(f"Geolocation info for {domain} found in database.")

        return jsonify({"domain": domain, "ip": ip_address, "geolocation": geolocation_data}), 200

    except Exception as e:
        logging.error(f"Error retrieving geolocation for {domain}: {e}")
        logging.error(traceback.format_exc())  # Logs full traceback for debugging
        return jsonify({"error": "An internal error occurred"}), 500

if __name__ == '__main__':
    init_db1()
    init_db2()
    init_db3()
    init_geolocation_db()
    
    logging.getLogger('flask_cors').level = logging.DEBUG
    app.run(port=8888, debug=True)
