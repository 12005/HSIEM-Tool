import datetime
import json
from config import RISK_WEIGHTS, KNOWN_SAFE_STARTUP_ITEMS

class VulnerabilityAssessment:
    def __init__(self, collected_data):
        self.data = collected_data
        self.risk_score = 0
        self.details = {}
        self.breakdown = {}  # Add this line

    def nist_risk_calc(self, threat=1, vulnerability=1, impact=1):
        """Calculate risk using NIST SP 800-30 formula."""
        return threat * vulnerability * impact
    
    def assess_processes(self):
        risk = 0
        suspicious_keywords = ['malware', 'virus', 'trojan', 'hacker']
        suspicious_processes = []
        behavioral_flags = []

        for proc in self.data.get('processes', []):
            process_name = proc.get('name', '').lower()

            if any(keyword in process_name for keyword in suspicious_keywords):
                threat = 4  # High chance of execution
                vuln = 4    # High if sus proc
                impact = 3  # Mid-level system impact
                risk += self.nist_risk_calc(threat, vuln, impact)
                suspicious_processes.append(proc)

            if proc.get('memory_percent', 0) > 30 or proc.get('cpu_percent', 0) > 50:
                threat = 3
                vuln = 2
                impact = 2
                risk += self.nist_risk_calc(threat, vuln, impact)
                behavioral_flags.append(proc)

        self.details['suspicious_processes'] = suspicious_processes
        self.details['behavioral_flags'] = behavioral_flags
        return risk


    def assess_network(self):
        risk = 0
        connections = self.data.get('network_connections', [])
        open_ports = set()
        high_ports = []

        for conn in connections:
            if conn.get('laddr'):
                try:
                    port = int(conn['laddr'].split(":")[-1])
                    open_ports.add(port)
                    if port > 1024:
                        high_ports.append(port)
                        risk += self.nist_risk_calc(threat=3, vulnerability=2, impact=2)
                except Exception:
                    continue

        if len(open_ports) > 10:
            risk += self.nist_risk_calc(threat=3, vulnerability=3, impact=3)

        self.details['open_ports'] = list(open_ports)
        self.details['unusual_ports'] = high_ports
        return risk


    def assess_digital_signatures(self):
        risk = 0
        failed_signatures = []
        for sig in self.data.get('digital_signatures', []):
            if not sig.get('signature_valid', False):
                risk += self.nist_risk_calc(threat=2, vulnerability=3, impact=2)
                failed_signatures.append(sig)
        self.details['failed_digital_signatures'] = failed_signatures
        return risk


    def assess_registry(self):
        risk = 0
        registry_data = self.data.get('registry', {})
        unknown_startup_items = {}

        if 'error' in registry_data:
            risk += self.nist_risk_calc(threat=2, vulnerability=2, impact=2)
        else:
            startup_items = registry_data.get("StartupItems", {})
            for item, cmd in startup_items.items():
                if item not in KNOWN_SAFE_STARTUP_ITEMS:
                    unknown_startup_items[item] = cmd
                    risk += self.nist_risk_calc(threat=2, vulnerability=3, impact=2)

            if len(startup_items) > 5:
                risk += self.nist_risk_calc(threat=2, vulnerability=2, impact=1)

        self.details['registry_data'] = registry_data
        self.details['unknown_startup_items'] = unknown_startup_items
        return risk


    def assess_nmap_vulnerabilities(self):
        risk = 0
        vulnerabilities = []
        for host_data in self.data.get('nmap_scan', []):
            if isinstance(host_data, dict) and 'error' not in host_data:
                risk += len(host_data.get('open_ports', [])) * self.nist_risk_calc(2, 2, 2)
                vuln_list = host_data.get('vulnerabilities', [])
                for vuln in vuln_list:
                    risk += self.nist_risk_calc(threat=4, vulnerability=4, impact=4)
                vulnerabilities.extend(vuln_list)
        self.details['nmap_vulnerabilities'] = vulnerabilities
        return risk


    def assess_threat_intel(self):
        # Placeholder for real threat intelligence integration
        self.details['threat_intelligence'] = "Simulated threat intelligence risk: 1"
        return RISK_WEIGHTS.get('threat_intel', 1)
    def assess_event_logs(self):
        risk = 0
        logs = self.data.get('event_logs', {})
        event_risk_details = {"windows": [], "linux": []}

        if logs:
            # Windows Event Log Risk Check
            if isinstance(logs, dict) and "Security" in logs:
                for log in logs.get("Security", []):
                    if isinstance(log, dict):
                        eid = log.get("EventID")
                        if eid == 4625:
                            risk += self.nist_risk_calc(threat=3, vulnerability=3, impact=2)
                            event_risk_details["windows"].append(f"Failed login attempt (EventID {eid})")
                        elif eid == 1102:
                            risk += self.nist_risk_calc(threat=4, vulnerability=4, impact=4)
                            event_risk_details["windows"].append("Audit logs cleared (EventID 1102)")
                        elif eid == 4688:
                            risk += 2
                            event_risk_details["windows"].append("Process execution logged (EventID 4688)")

            # Linux Syslog Risk Check
            for log_type, lines in logs.items():
                if isinstance(lines, list):
                    for line in lines:
                        if "Failed password" in line:
                            risk += self.nist_risk_calc(threat=3, vulnerability=3, impact=2)
                            event_risk_details["linux"].append("Failed SSH login detected")
                        elif "sudo" in line and "authentication failure" in line:
                            risk += 2
                            event_risk_details["linux"].append("Sudo auth failure")

        self.details["event_log_flags"] = event_risk_details
        return risk

    def compute_risk_score(self):
        self.risk_score += self.assess_processes()
        self.risk_score += self.assess_network()
        self.risk_score += self.assess_digital_signatures()
        self.risk_score += self.assess_registry()
        self.risk_score += self.assess_nmap_vulnerabilities()
        self.risk_score += self.assess_threat_intel()
        self.risk_score += self.assess_event_logs()
        return self.risk_score

    def get_severity(self):
        if self.risk_score < 5:
            return "Low"
        elif self.risk_score < 10:
            return "Medium"
        else:
            return "High"

    def get_report(self):
        return {
            "risk_score": self.risk_score,
            "severity": self.get_severity(),
            "details": self.details,
            "timestamp": datetime.datetime.now().isoformat()
        }
