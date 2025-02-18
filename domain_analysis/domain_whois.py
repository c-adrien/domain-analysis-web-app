import sqlite3
import logging
import os
import time
from typing import Optional, Dict
from globals import *
import subprocess

#-------------------------------
# FUNCTIONS - DB
#-------------------------------

def init_db() -> None:
    """Initializes the SQLite database with both 'subdomains' and 'whois_info' tables."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whois_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,  -- Domain should be unique in whois_info
                    registrar TEXT,
                    creation_date TEXT,
                    expiration_date TEXT,
                    name_servers TEXT,
                    organization TEXT,
                    admin_contact TEXT,
                    raw_text TEXT,  -- Store the raw WHOIS output (optional)
                    timestamp REAL
                )
            """)
            conn.commit()  # Commit both table creations
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {e}")
        exit(1)


#-------------------------------
# FUNCTIONS - WHOIS
#-------------------------------

def get_whois_info(domain: str, timeout: int = 5) -> Optional[Dict[str, str]]:
    """Retrieves WHOIS information for a domain with a timeout.

    Args:
        domain: The domain to query.
        timeout: Timeout in seconds for the WHOIS lookup.

    Returns:
        A dictionary containing WHOIS information, or None if an error occurs
        or no data is found.
    """
    try:
        result = subprocess.run(
            ["whois", domain], 
            capture_output=True, text=True, timeout=timeout
        )

        if result.returncode != 0:
            logging.error(f"WHOIS lookup failed for {domain}: {result.stderr}")
            return None
        
        raw_whois = result.stdout
        logging.info(f"WHOIS info for {domain} retrieved")

        # Parse the WHOIS output (basic parsing example)
        whois_data = {
            "registrar": _extract_field(raw_whois, r"(?i)Registrar:\s*(.+)"),
            "creation_date": _extract_field(raw_whois, r"Creation Date:\s*(.+)"),
            "expiration_date": _extract_field(raw_whois, r"Expiration Date:\s*(.+)"),
            "name_servers": _extract_nameservers(raw_whois),
            "organization": _extract_field(raw_whois, r"Registrant Organization:\s*(.+)"),
            "admin_contact": _extract_field(raw_whois, r"Admin Email:\s*(.+)"),
            "raw_text": raw_whois,  # Store raw WHOIS output
        }

        return whois_data

    except subprocess.TimeoutExpired:
        logging.error(f"WHOIS lookup for {domain} timed out after {timeout} seconds")
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")

    return None

def _extract_field(text: str, pattern: str) -> Optional[str]:
    """Helper function to extract a single field from WHOIS output using regex."""
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).strip() if match else None

def _extract_nameservers(text: str) -> Optional[str]:
    """Extracts all name servers from WHOIS output."""
    matches = re.findall(r"(?i)(?:Name\s*Server|nserver):\s*(\S+)", text)
    
    return ", ".join(matches) if matches else None


def whois_recently_retrieved(domain: str) -> bool:
    """Checks if WHOIS information for a domain has been retrieved recently.

    Args:
        domain: The domain to check.

    Returns:
        True if WHOIS information has been retrieved recently, False otherwise.
    """
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT MAX(timestamp) FROM whois_info WHERE domain = ?", (domain,))

            result = cursor.fetchone()

            if result and result[0]:
                last_updated = result[0]
                current_time = time.time()
                if current_time - last_updated < SCAN_THRESHOLD_SECONDS:
                    logging.info(f"Recent WHOIS info exists for {domain}, skipping.")
                    return True
            return False
    except sqlite3.Error as e:
        logging.error(f"Database error checking WHOIS retrieval time: {e}")
        return False


def save_whois_info_to_db(domain: str, whois_data: Dict[str, str]) -> None:
    """Saves WHOIS information to the 'whois_info' table."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()
            timestamp = time.time()

            cursor.execute("""
                INSERT OR IGNORE INTO whois_info (domain, registrar, creation_date, expiration_date, name_servers, organization, admin_contact, raw_text, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (domain, whois_data.get("registrar"), whois_data.get("creation_date"), whois_data.get("expiration_date"), whois_data.get("name_servers"), whois_data.get("organization"), whois_data.get("admin_contact"), whois_data.get("raw_text"), timestamp))  # Use .get to handle missing keys
            conn.commit()
            logging.info(f"WHOIS info saved for {domain}")
    except sqlite3.Error as e:
        logging.error(f"Database error saving WHOIS info: {e}")


#-------------------------------
# MAIN
#-------------------------------

def main(domain_input: str) -> None:
    """Main function to retrieve and save WHOIS information.

    Handles both second-level domains and subdomains.  If a subdomain is
    provided, it extracts the second-level domain before performing
    the WHOIS lookup.

    Args:
        domain_input: The domain or subdomain to check.
    """
    init_db()

    if not is_ip_address(domain_input) and not is_second_level_domain(domain_input):  # Check if it's a subdomain
        parts = domain_input.split(".")
        if len(parts) > 2: # Check if it is a subdomain and not a TLD
            domain_to_check = ".".join(parts[-2:])  # Extract the second-level domain
        else:
            logging.error(f"Invalid domain: {domain_input}")
            return
    else:
        domain_to_check = domain_input


    logging.info(f"Checking domain: {domain_to_check}")

    if whois_recently_retrieved(domain_to_check):
        return
    
    else:
        whois_info = get_whois_info(domain_to_check)

        if whois_info:
            save_whois_info_to_db(domain_to_check, whois_info)
        else:
            logging.error(f"Could not retrieve WHOIS information for {domain_to_check}")


if __name__ == "__main__":
    domain_to_check = "play.google.com"  # Example subdomain
    main(domain_to_check)

    domain_to_check = "google.com"  # Example second-level domain
    main(domain_to_check)

    domain_to_check = "invalid.domain.com" # Example Invalid domain
    main(domain_to_check)

    domain_to_check = "8.8.8.8"
    main(domain_to_check)