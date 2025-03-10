# Risk Weights Configuration
RISK_WEIGHTS = {
    'suspicious_process': 5,
    'suspicious_behavior': 2,
    'failed_signature': 2,
    'high_open_ports': 3,
    'unusual_port': 1,
    'registry_error': 2,
    'unknown_registry': 2,
    'excessive_startup_items': 2,
    'vulnerability_found': 3,
    'port_risk_weight': 0.5,
    'threat_intel': 1
}

# Known Safe Startup Items (Whitelist)
KNOWN_SAFE_STARTUP_ITEMS = [
    "OneDrive",
    "Windows Defender",
    "Realtek Audio Manager",
    "Intel Graphics Command Center",
    "Google Chrome",
    "Microsoft Edge",
    "Dropbox",
    "Adobe Updater",
    "Zoom",
    "Slack"
]
