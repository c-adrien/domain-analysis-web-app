import sqlite3
import logging
import os
import requests
import time
import json
from typing import Dict, Optional
from globals import *

# -------------------------------
# DATABASE INITIALIZATION
# -------------------------------
def init_db() -> None:
    """Initializes the SQLite database with a table for security headers."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_headers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    header_name TEXT,
                    header_value TEXT,
                    header_risk TEXT,
                    header_description TEXT,
                    timestamp REAL
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {e}")
        exit(1)

# -------------------------------
# FETCH AND EXTRACT HEADERS
# -------------------------------
def fetch_security_headers(url: str) -> Dict[str, str]:
    """Fetches HTTP response headers from the given URL."""
    try:
        response = requests.get(url, timeout=10)
        return response.headers
    except requests.RequestException as e:
        logging.error(f"Failed to fetch headers from {url}: {e}")
        return {}

# -------------------------------
# ANALYZE SECURITY HEADERS
# -------------------------------
def analyze_headers(headers: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """Analyzes security headers and identifies risks."""
    analysis = {}

    # Security-related headers to check
    security_headers = {
        "Content-Security-Policy": "CSP restricts content sources, preventing XSS attacks.",
        "Strict-Transport-Security": "HSTS forces HTTPS to prevent man-in-the-middle attacks.",
        "X-Content-Type-Options": "Prevents MIME-sniffing attacks.",
        "X-Frame-Options": "Protects against clickjacking.",
        "X-XSS-Protection": "Deprecated but was used for basic XSS protection.",
        "Referrer-Policy": "Controls how much referrer info is sent.",
        # "Permissions-Policy": "Restricts browser features like microphone, camera."
    }

    for header, description in security_headers.items():
        value = headers.get(header, "Not Set")
        risk = "None" if value != "Not Set" else "Missing"
        analysis[header] = {
            "value": value,
            "risk": risk,
            "description": description
        }

    # Special checks for weak policies
    if "Content-Security-Policy" in headers:
        csp_value = headers["Content-Security-Policy"]
        if "unsafe-inline" in csp_value or "unsafe-eval" in csp_value:
            analysis["Content-Security-Policy"]["risk"] = "Weak (Allows unsafe scripts)"

    return analysis

# -------------------------------
# STORE HEADERS IN DATABASE
# -------------------------------
def store_headers(url: str, headers_analysis: Dict[str, Dict[str, str]]) -> None:
    """Stores extracted and analyzed security headers into the database."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()
            timestamp = time.time()

            for header, data in headers_analysis.items():
                cursor.execute("""
                    INSERT INTO security_headers (url, header_name, header_value, header_risk, header_description, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (url, header, data["value"], data["risk"], data["description"], timestamp))
            
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Failed to store headers in database: {e}")

# -------------------------------
# MAIN EXECUTION
# -------------------------------
def main(URL: str) -> None:
    if not URL.startswith("https://"):
        URL = "https://" + URL

    init_db()
    headers = fetch_security_headers(URL)
    if headers:
        analyzed_headers = analyze_headers(headers)
        store_headers(URL, analyzed_headers)
        
        print("\nExtracted & Analyzed Security Headers:")
        for header, data in analyzed_headers.items():
            print(f"\n{header}: {data['value']}")
            print(f"  ➜ Risk: {data['risk']}")
            print(f"  ➜ Description: {data['description']}")
    else:
        print("Failed to retrieve headers.")


if __name__ == "__main__":
    main("reddit.com")
