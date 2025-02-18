#-------------------------------
# IMPORTS
#-------------------------------

import subprocess
import sqlite3
import dns.resolver
import logging
import os
import time
from typing import List, Dict, Optional, Union, Set
import re
import json
import requests
from globals import *

#-------------------------------
# FUNCTIONS - DB
#-------------------------------

def init_db() -> None:
    """Initializes the SQLite database if it doesn't exist."""
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:  # Use context manager
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    subdomain TEXT UNIQUE,
                    ip TEXT,
                    timestamp REAL
                )
            """)
            conn.commit()  # Commit within the context manager
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {e}")
        exit(1) # Exit if database init fails


def save_to_db(domain: str, resolved_data: Dict[str, Optional[str]]) -> None:
    """Saves resolved subdomain data to the database.

    Handles both second-level domains (added to the 'domain' column) and
    subdomains (added to the 'subdomain' column).

    Args:
        domain: The domain or subdomain.
        resolved_data: A dictionary of subdomains and their IP addresses.
    """
    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()
            timestamp = time.time()

            parts = domain.split(".")
            if not is_second_level_domain(domain):  # It's a subdomain
                if len(parts) > 2:
                    root_domain = ".".join(parts[-2:])  # Extract the root domain
                else:
                    return

                for sub, ip in resolved_data.items():
                    # First check if the subdomain already exists in the database
                    cursor.execute("""
                        SELECT id FROM subdomains WHERE domain = ? AND subdomain = ?
                    """, (root_domain, sub))
                    existing_row = cursor.fetchone()

                    if existing_row:
                        # If it exists, update the timestamp and IP address
                        cursor.execute("""
                            UPDATE subdomains
                            SET timestamp = ?, ip = ?
                            WHERE id = ?
                        """, (timestamp, ip, existing_row[0]))
                    else:
                        # If it doesn't exist, insert a new row
                        cursor.execute("""
                            INSERT INTO subdomains (domain, subdomain, ip, timestamp)
                            VALUES (?, ?, ?, ?)
                        """, (root_domain, sub, ip, timestamp))

                conn.commit()

            else:  # It's a second-level domain
                for sub, ip in resolved_data.items():
                    # First check if the domain already exists in the database
                    cursor.execute("""
                        SELECT id FROM subdomains WHERE domain = ? AND subdomain = ?
                    """, (domain, sub))
                    existing_row = cursor.fetchone()

                    if existing_row:
                        # If it exists, update the timestamp and IP address
                        cursor.execute("""
                            UPDATE subdomains
                            SET timestamp = ?, ip = ?
                            WHERE id = ?
                        """, (timestamp, ip, existing_row[0]))
                    else:
                        # If it doesn't exist, insert a new row
                        cursor.execute("""
                            INSERT INTO subdomains (domain, subdomain, ip, timestamp)
                            VALUES (?, ?, ?, ?)
                        """, (domain, sub, ip, timestamp))

                conn.commit()

            logging.info("Results saved to database")
    except sqlite3.Error as e:
        logging.error(f"Database error saving data: {e}")



def domain_recently_scanned(domain: str) -> bool:
    """Checks if a domain has been scanned recently.

    Args:
        domain: The domain to check.

    Returns:
        True if the domain has been scanned recently, False otherwise.
    """

    try:
        with sqlite3.connect(os.path.join(BASE_DIR, DB_FILE)) as conn:
            cursor = conn.cursor()

            if not is_second_level_domain(domain):
                cursor.execute("SELECT MAX(timestamp) FROM subdomains WHERE subdomain = ?", (domain,))
            else:
                cursor.execute("SELECT MAX(timestamp) FROM subdomains WHERE domain = ?", (domain,))
            result = cursor.fetchone()

            if result and result[0]:
                last_updated = result[0]

                current_time = time.time()
                if current_time - last_updated < SCAN_THRESHOLD_SECONDS:
                    logging.info(f"Recent scan exists for {domain}, skipping.")
                    return True
            return False
    except sqlite3.Error as e:
        init_db()
        return False

#-------------------------------
# FUNCTIONS - Sublist3r
#-------------------------------

def run_sublist3r(domain: str, retry: bool = False) -> Set[str]:
    """Runs Sublist3r to discover subdomains.

    Args:
        domain: The domain to scan.

    Returns:
        A list of subdomains found.
    """
    try:
        logging.info(f"Running Sublist3r on {domain}...")
        result = subprocess.run(
            ["python3", SUBLIST3R_PATH, "-d", domain, "-o", SUBDOMAINS_FILE],
            capture_output=True,
            text=True,
            check=True,  # Raise exception for non-zero exit code
            timeout=60 # Set a timeout (1 minute)
        )
        # Log stderr if there's any
        if result.stderr:
          logging.warning(f"Sublist3r stderr: {result.stderr}")

        with open(SUBDOMAINS_FILE, "r") as file:
            subdomains = file.read().splitlines()

        os.remove(SUBDOMAINS_FILE)
        return set(subdomains)
    except subprocess.CalledProcessError as e:
        logging.error(f"Sublist3r execution failed: {e}")
        if e.stderr:
            logging.error(f"Sublist3r stderr: {e.stderr}")
        return ()
    except FileNotFoundError:
        logging.error(f"Sublist3r script not found at: {SUBLIST3R_PATH}")
        if retry: 
            return ()
        else:
            return run_sublist3r(domain, retry=True)
    except subprocess.TimeoutExpired:
        logging.error(f"Sublist3r timed out.")
        return ()
    except Exception as e:
        logging.error(f"Error running Sublist3r: {e}")
        return ()
    

#-------------------------------
# FUNCTIONS - crtsh
#-------------------------------

def is_valid_domain(name: str, domain: str) -> bool:
    """
    Checks if a given name is a valid domain or subdomain and does not
    resemble an email address.  It also checks if the name ends with the
    target domain.

    Args:
        name: The name to check (e.g., "*.google.com", "sub.google.com", "admin@google.com").
        domain: The target domain (e.g., "google.com").

    Returns:
        True if the name is a valid domain/subdomain and not an email, False otherwise.
    """

    if not name:  # Handle empty names
        return False

    if re.match(r"[^@]+@[^@]+\.[^@]+", name):  # Check for email format
        return False

    if not name.endswith(domain): # Check if it ends with the target domain
        return False

    return True


def remove_wildcard(url: str) -> str:
    """Removes the wildcard prefix "*." from a URL if present.

    Args:
        url: The URL string.

    Returns:
        The URL with the wildcard removed, or the original URL if no wildcard is found
        or if the input is None. Returns an empty string if the input is an empty string.
    """

    if url is None:  # Handle None input
        return None

    if not url: # Handle empty string input
        return None
    
    url = url.strip()

    if url.startswith("*."):
        return url[2:]  # Slice the string to remove the "*."
    return url


def get_crtsh_data(domain: str) -> Set[str]:
    """
    Retrieves certificate information from crt.sh and extracts common names and
    name values, excluding entries that look like usernames (e.g., admin@domain.com).

    Args:
        domain: The domain to query (e.g., "google.com").

    Returns:
        A list of unique FQDNs extracted from the certificates.  Returns an empty
        list if there's an error or no data is found.
    """

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:

        retries = 3
        for attempt in range(retries):
            try:
                response = requests.get(url, timeout=20)  # Add a timeout
                response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
                data = response.json()

                fqdns = set()

                for entry in data:
                    common_name = entry.get("common_name")
                    name_value = entry.get("name_value")

                    if common_name and is_valid_domain(common_name, domain):
                        fqdns.add(remove_wildcard(name))

                    if name_value:
                        names = name_value.splitlines()
                        for name in names:
                            if is_valid_domain(name.strip(), domain):
                                fqdns.add(remove_wildcard(name))

                return fqdns
            except requests.exceptions.RequestException as e:
                logging.error(f"crt.sh request failed : attempt {attempt + 1}, retrying... {e}")
                time.sleep(5)
            except requests.exceptions.ReadTimeout:
                logging.warning(f"crt.sh request timed out: attempt {attempt + 1}, retrying...")
                time.sleep(5)
        logging.error("Failed after retries.")
        return ()


    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from crt.sh: {e}")
        return ()
    except (json.JSONDecodeError, TypeError) as e:  # Handle JSON decoding and type errors
        logging.error(f"Error processing crt.sh response: {e}")
        return ()
    except Exception as e: # Catch any other unexpected exceptions
        logging.error(f"An unexpected error occurred: {e}")
        return ()
    
    
#-------------------------------
# FUNCTIONS - DNS
#-------------------------------

def resolve_subdomains(subdomains: List[str]) -> Dict[str, Optional[str]]:
    """Resolves subdomains to IP addresses.

    Args:
        subdomains: A list of subdomains.

    Returns:
        A dictionary mapping subdomains to their IP addresses (or None if resolution fails).
    """
    resolved = {}
    resolver = dns.resolver.Resolver()
    
    for sub in subdomains:
        try:
            answers = resolver.resolve(sub, "A")  # Get all A records
            ips = [ip.to_text() for ip in answers] # Handle multiple IPs
            resolved[sub] = ", ".join(ips) if ips else None # Store as comma-separated
        except dns.resolver.NXDOMAIN:
            logging.warning(f"Could not resolve {sub}: No such domain")
            resolved[sub] = None
        except dns.resolver.NoAnswer:
            logging.warning(f"Could not resolve {sub}: No answer")
            resolved[sub] = None
        except dns.resolver.Timeout:
            logging.warning(f"DNS resolution timed out for {sub}")
            resolved[sub] = None
        except Exception as e:
            logging.error(f"Error resolving {sub}: {e}")
            resolved[sub] = None
    return resolved

#-------------------------------
# MAIN
#-------------------------------

def main(domain: str) -> None:
    """Main function to perform subdomain enumeration and resolution.

    Args:
        domain: The target domain.
    """
    if domain_recently_scanned(domain):
        return

    subdomains = set()
    if not is_second_level_domain(domain):
        subdomains.update((domain,))
    subdomains.update(run_sublist3r(domain))
    subdomains.update(get_crtsh_data(domain))
     
    if not subdomains:
        logging.info("No subdomains found!")
        return

    resolved_data = resolve_subdomains(subdomains)
    save_to_db(domain, resolved_data)

    logging.info("Scan Complete!")
    for sub, ip in resolved_data.items():
        logging.info(f"{sub} -> {ip}")


if __name__ == "__main__":
    main("play.google.com")
    main("google.com")