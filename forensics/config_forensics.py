# config_forensics.py

import os

# Base paths
FORENSICS_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(FORENSICS_BASE_DIR, "rules")
TEMP_DIR = os.path.join(FORENSICS_BASE_DIR, "temp")
TEST_DIR = os.path.join(os.getcwd(), "test")  # Used by multiple modules

# YARA paths
YARA_RULES_DIR = os.path.join(RULES_DIR, "yara")
YARA_INDEX_FILE = os.path.join(YARA_RULES_DIR, "index.yar")

# Rule categories
YARA_CATEGORIES = {
    "malware": os.path.join(YARA_RULES_DIR, "malware"),
    "ransomware": os.path.join(YARA_RULES_DIR, "ransomware"),
    "webshells": os.path.join(YARA_RULES_DIR, "webshells"),
    "exploits": os.path.join(YARA_RULES_DIR, "exploits"),
    "suspicious": os.path.join(YARA_RULES_DIR, "suspicious")
}

# Risk scores for different rule categories
YARA_RISK_SCORES = {
    "malware": 8.0,
    "ransomware": 9.0,
    "webshells": 7.0,
    "exploits": 7.5,
    "suspicious": 5.0
}
