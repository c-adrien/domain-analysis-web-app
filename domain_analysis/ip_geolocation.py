import sqlite3
import logging
import os
import time
import subprocess
import requests
from typing import Optional
from globals import *

# -------------------------------
# FUNCTIONS - DB
# -------------------------------

def init_geolocation_db() -> None:
    """Initializes the SQLite database with 'ip_geolocation' table."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_geolocation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,  -- Domain should be unique in ip_geolocation
                    ip_address TEXT,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    timestamp REAL
                )
            """)
            conn.commit()  # Commit table creation
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {e}")
        exit(1)

# -------------------------------
# FUNCTIONS - NSLOOKUP and IP Geolocation
# -------------------------------

def get_ip_from_nslookup(domain: str) -> Optional[str]:
    """Performs nslookup to resolve the IP address of the domain, extracting only the IP address."""
    try:
        result = subprocess.run(
            ["nslookup", domain], 
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            logging.error(f"NSLookup failed for {domain}: {result.stderr}")
            return None
        
        # Parse nslookup output to extract the IP address from the Answer section
        lines = result.stdout.splitlines()
        ip_address = None
        
        # Find the start of the 'Non-authoritative answer' section and look for the Address lines
        found_answer_section = False
        for line in lines:
                
            # Once we find the 'Non-authoritative answer' section, look for Address: lines
            if "Non-authoritative answer:" in line:
                found_answer_section = True
                continue
            
            if found_answer_section and "Address:" in line:
                # Extract IP address after 'Address:'
                ip_address = line.split(":")[1].strip()
                if ip_address:
                    break

        if ip_address:
            return ip_address
        else:
            logging.error(f"No valid IP address found for {domain}")
            return None

    except Exception as e:
        logging.error(f"Error performing nslookup for {domain}: {e}")
        return None
    

def get_ip_geolocation(ip_address: str) -> Optional[dict]:
    """Fetches geolocation information based on IP address using ip-api.com."""
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        print(url)
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            
            if data["status"] == "fail":
                logging.error(f"Geolocation lookup failed for {ip_address}: {data.get('message')}")
                return None

            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon")
            }
        
        logging.error(f"Failed to get geolocation for {ip_address}")
        return None
    except Exception as e:
        logging.error(f"Error fetching geolocation data for {ip_address}: {e}")
        return None

def save_geolocation_to_db(domain: str, ip_address: str, geolocation_data: dict) -> None:
    """Saves geolocation data to the 'ip_geolocation' table."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()
            timestamp = time.time()

            cursor.execute("""
                INSERT OR IGNORE INTO ip_geolocation (domain, ip_address, country, region, city, latitude, longitude, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (domain, ip_address, geolocation_data.get("country"), geolocation_data.get("region"), 
                  geolocation_data.get("city"), geolocation_data.get("latitude"), 
                  geolocation_data.get("longitude"), timestamp))
            conn.commit()
            logging.info(f"Geolocation info saved for {domain}")
    except sqlite3.Error as e:
        logging.error(f"Database error saving geolocation info: {e}")

# -------------------------------
# MAIN FUNCTION
# -------------------------------

def main(domain_input: str) -> None:
    """Main function to retrieve and save IP geolocation information for a domain."""
    init_geolocation_db()

    # Get IP address from nslookup
    ip_address = get_ip_from_nslookup(domain_input)

    if not ip_address:
        logging.error(f"Could not resolve IP address for {domain_input}")
        return
    
    logging.info(f"Resolved IP address for {domain_input}: {ip_address}")
    
    # Get geolocation information
    geolocation_data = get_ip_geolocation(ip_address)

    if geolocation_data:
        # Save geolocation data to DB
        save_geolocation_to_db(domain_input, ip_address, geolocation_data)
    else:
        logging.error(f"Could not retrieve geolocation information for {ip_address}")


if __name__ == "__main__":
    # Example usage
    domain_input = "play.google.com"  # Example domain
    main(domain_input)

    domain_input = "google.com"  # Example domain
    main(domain_input)

    domain_input = "invalid.domain.com"  # Example Invalid domain
    main(domain_input)
