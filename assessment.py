import datetime
import json
from config import RISK_WEIGHTS, KNOWN_SAFE_STARTUP_ITEMS

class VulnerabilityAssessment:
    def __init__(self, collected_data):
        self.data = collected_data
        self.risk_score = 0
        self.details = {}

    def assess_processes(self):
        risk = 0
        suspicious_keywords = ['malware', 'virus', 'trojan', 'hacker']
        suspicious_processes = []
        behavioral_flags = []

        for proc in self.data.get('processes', []):
            process_name = proc.get('name', '').lower()
            for keyword in suspicious_keywords:
                if keyword in process_name:
                    risk += RISK_WEIGHTS.get('suspicious_process', 5)
                    suspicious_processes.append(proc)
                    break

            # Behavioral heuristic (simulate abnormal behavior risk)
            if proc.get('memory_percent', 0) > 30 or proc.get('cpu_percent', 0) > 50:
                risk += RISK_WEIGHTS.get('suspicious_behavior', 2)
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
                        risk += RISK_WEIGHTS.get('unusual_port', 1)
                except Exception:
                    continue

        if len(open_ports) > 10:
            risk += RISK_WEIGHTS.get('high_open_ports', 3)

        self.details['open_ports'] = list(open_ports)
        self.details['unusual_ports'] = high_ports
        return risk

    def assess_digital_signatures(self):
        risk = 0
        failed_signatures = []
        for sig in self.data.get('digital_signatures', []):
            if not sig.get('signature_valid', False):
                risk += RISK_WEIGHTS.get('failed_signature', 2)
                failed_signatures.append(sig)
        self.details['failed_digital_signatures'] = failed_signatures
        return risk

    def assess_registry(self):
        risk = 0
        registry_data = self.data.get('registry', {})

        unknown_startup_items = {}
        if 'error' in registry_data:
            risk += RISK_WEIGHTS.get('registry_error', 2)
        else:
            startup_items = registry_data.get("StartupItems", {})
            for item, cmd in startup_items.items():
                if item not in KNOWN_SAFE_STARTUP_ITEMS:
                    unknown_startup_items[item] = cmd
                    risk += RISK_WEIGHTS.get('unknown_registry', 2)

            if len(startup_items) > 5:
                risk += RISK_WEIGHTS.get('excessive_startup_items', 2)

        self.details['registry_data'] = registry_data
        self.details['unknown_startup_items'] = unknown_startup_items
        return risk

    def assess_nmap_vulnerabilities(self):
        risk = 0
        vulnerabilities = []
        for host_data in self.data.get('nmap_scan', []):
            if isinstance(host_data, dict) and 'error' not in host_data:
                risk += len(host_data.get('open_ports', [])) * RISK_WEIGHTS.get('port_risk_weight', 0.5)
                vuln_list = host_data.get('vulnerabilities', [])
                risk += len(vuln_list) * RISK_WEIGHTS.get('vulnerability_found', 3)
                vulnerabilities.extend(vuln_list)
        self.details['nmap_vulnerabilities'] = vulnerabilities
        return risk

    def assess_threat_intel(self):
        # Placeholder for real threat intelligence integration
        self.details['threat_intelligence'] = "Simulated threat intelligence risk: 1"
        return RISK_WEIGHTS.get('threat_intel', 1)

    def compute_risk_score(self):
        self.risk_score += self.assess_processes()
        self.risk_score += self.assess_network()
        self.risk_score += self.assess_digital_signatures()
        self.risk_score += self.assess_registry()
        self.risk_score += self.assess_nmap_vulnerabilities()
        self.risk_score += self.assess_threat_intel()
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
