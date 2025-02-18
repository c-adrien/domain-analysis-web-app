import logging
import os
import re

#-------------------------------
# CONSTANTS
#-------------------------------

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUBLIST3R_PATH = os.path.join(BASE_DIR, "Sublist3r", "sublist3r.py")
SUBDOMAINS_FILE = "subdomains.txt"
DB_FILE = os.path.join(BASE_DIR, "recon.db")
SCAN_THRESHOLD_SECONDS = 3600

#-------------------------------
# MACROS
#-------------------------------

def is_second_level_domain(domain: str) -> bool:
    """Checks if a domain is a second-level domain (e.g., example.com, but not sub.example.com or example.co.uk)."""
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z]{2,6})", domain, re.IGNORECASE))


def is_ip_address(ip_string: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address.

    Args:
        ip_string: The string to check.

    Returns:
        True if the string is a valid IP address, False otherwise.
    """
    try:
        import ipaddress  # Import ipaddress inside the function for better dependency management
        ipaddress.ip_address(ip_string) # will raise ValueError if invalid
        return True
    except ValueError:
        return False
