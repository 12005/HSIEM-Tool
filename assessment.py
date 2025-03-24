import datetime
import json
from config_risk import RISK_WEIGHTS, KNOWN_SAFE_STARTUP_ITEMS

MAX_THREAT = 5
MAX_VULNERABILITY = 5
MAX_IMPACT = 5
MAX_RISK_SCORE_PER_EVENT = MAX_THREAT * MAX_VULNERABILITY * MAX_IMPACT  # 125

class VulnerabilityAssessment:
    def __init__(self, collected_data):
        self.data = collected_data
        self.risk_score = 0
        self.total_raw_risk_score = 0  #
        self.details = {}
        self.breakdown = {}
        self.details['suspicious_processes'] = []
        self.details['registry_anomalies'] = []
        self.details['known_safe_items'] = KNOWN_SAFE_STARTUP_ITEMS
        self.recommendations = []

    def nist_risk_calc(self, threat, vulnerability, impact, label=None):
        raw_score = threat * vulnerability * impact
        normalized_score = (raw_score / MAX_RISK_SCORE_PER_EVENT) * 10  # Each risk event max = 10 points

        self.total_raw_risk_score += raw_score  # Track for metrics
        if label:
            self.breakdown[label] = {
                "threat": threat,
                "vulnerability": vulnerability,
                "impact": impact,
                "raw_score": raw_score,
                "normalized_score": normalized_score
            }

        return normalized_score

    def assess_processes(self):
        risk = 0
        suspicious_keywords = {
            'malware': 5,
            'virus': 4,
            'trojan': 5,
            'hacker': 3,
            'backdoor': 5,
            'keylogger': 4
        }

        for proc in self.data.get('processes', []):
            process_name = proc.get('name', '').lower()
            proc_label = f"proc_{proc.get('pid', 'unknown')}"

            for keyword, threat_level in suspicious_keywords.items():
                if keyword in process_name:
                    self.details['suspicious_processes'].append(proc)
                    score = self.nist_risk_calc(
                        threat=threat_level,
                        vulnerability=4,
                        impact=3,
                        label=f"{proc_label}_keyword_{keyword}"
                    )
                    risk += score
                
            cpu_percent = proc.get('cpu_percent', 0)
            mem_percent = proc.get('memory_percent', 0)

            if cpu_percent > 80 or mem_percent > 80:
                score = self.nist_risk_calc(
                    threat=4,
                    vulnerability=3,
                    impact=4,
                    label=f"{proc_label}_high_cpu_or_mem"
                )
                risk += score

            elif cpu_percent > 50 or mem_percent > 50:
                score = self.nist_risk_calc(
                    threat=3,
                    vulnerability=2,
                    impact=3,
                    label=f"{proc_label}_moderate_cpu_or_mem"
                )
                risk += score
            if 'suspicious_processes' in self.details and self.details['suspicious_processes']:
                self.recommendations.append("Investigate and terminate suspicious processes. Ensure they are not malware.")

        return risk

    def assess_network(self):
        risk = 0
        connections = self.data.get('network_connections', [])
        open_ports = set()
        high_ports = []
        open_port_data = []

        # Risk classification based on port/service
        service_risk_mapping = {
            'ftp': 4,
            'telnet': 5,
            'ssh': 2,
            'http': 2,
            'https': 1,
            'rdp': 4,
            'smb': 5,
            'vnc': 4,
            'mysql': 3,
            'postgres': 3,
            'mongodb': 4,
            'dns': 2
        }

        # You can expand this dictionary over time 👆

        for idx, conn in enumerate(connections):
            if conn.get('laddr'):
                try:
                    port = int(conn['laddr'].split(":")[-1])
                    open_ports.add(port)

                    # Try to infer the service (optional if not using scan data)
                    service_name = "unknown"
                    for port_entry in self.data.get("nmap_scan", []):
                        if isinstance(port_entry, dict) and 'open_ports' in port_entry:
                            for nmap_port in port_entry['open_ports']:
                                if nmap_port['port'] == port:
                                    service_name = nmap_port.get('service', 'unknown').lower()

                    service_threat = service_risk_mapping.get(service_name, 2 if port > 1024 else 1)

                    if service_threat >= 4:
                        risk_level = "Critical Service"
                    elif service_threat == 3:
                        risk_level = "Medium Risk"
                    else:
                        risk_level = "Low Risk"

                    open_port_data.append({
                        "number": port,
                        "state": "open",
                        "risk": risk_level,
                        "service": service_name
                    })

                    # Dynamically adjust risk based on service
                    score = self.nist_risk_calc(
                        threat=service_threat,
                        vulnerability=2,
                        impact=service_threat,  # If critical service = higher impact
                        label=f"network_port_{port}_{service_name}_conn_{idx}"
                    )
                    risk += score

                except Exception:
                    continue

        if len(open_ports) > 10:
            score = self.nist_risk_calc(
                threat=3,
                vulnerability=3,
                impact=3,
                label="network_too_many_open_ports"
            )
            risk += score
            
        if len(open_ports) > 10:
            self.recommendations.append("Reduce the number of open ports. Disable unused services and restrict ports via firewall.")
        for port_data in open_port_data:
            if port_data['risk'] == "Critical Service":
                self.recommendations.append(f"Secure or restrict access to service '{port_data['service']}' on port {port_data['number']}.")

        self.details['open_ports'] = open_port_data
        self.details['unusual_ports'] = high_ports
        return risk

    def assess_digital_signatures(self):
        risk = 0
        failed_signatures = []

        for idx, sig in enumerate(self.data.get('digital_signatures', [])):
            if not sig.get('signature_valid', False):
                label = f"signature_invalid_file_{idx}"

                score = self.nist_risk_calc(
                    threat=2,
                    vulnerability=3,
                    impact=2,
                    label=label
                )
                risk += score
                failed_signatures.append(sig)

        self.details['failed_digital_signatures'] = failed_signatures
        
        if self.details['failed_digital_signatures']:
            self.recommendations.append("Reinstall unsigned or unverified software. Ensure software is from trusted sources.")

        return risk


    def assess_registry(self):
        risk = 0
        registry_data = self.data.get('registry', {})
        unknown_startup_items = {}

        if 'error' in registry_data:
            score = self.nist_risk_calc(
                threat=2,
                vulnerability=2,
                impact=2,
                label="registry_access_error"
            )
            risk += score
        else:
            startup_items = registry_data.get("StartupItems", {})
            for idx, (item, cmd) in enumerate(startup_items.items()):
                if item not in KNOWN_SAFE_STARTUP_ITEMS:
                    unknown_startup_items[item] = cmd
                    score = self.nist_risk_calc(
                        threat=2,
                        vulnerability=3,
                        impact=2,
                        label=f"registry_unknown_startup_item_{idx}_{item}"
                    )
                    risk += score

            if len(startup_items) > 5:
                score = self.nist_risk_calc(
                    threat=2,
                    vulnerability=2,
                    impact=1,
                    label="registry_excessive_startup_items"
                )
                risk += score

        self.details['registry_data'] = registry_data
        self.details['unknown_startup_items'] = unknown_startup_items
        
        if self.details.get('unknown_startup_items'):
            self.recommendations.append("Review unknown startup registry items. Disable anything suspicious or unnecessary.")


        return risk

    def assess_nmap_vulnerabilities(self):
        risk = 0
        vulnerabilities = []

        for host_idx, host_data in enumerate(self.data.get('nmap_scan', [])):
            if isinstance(host_data, dict) and 'error' not in host_data:
                open_ports = host_data.get('open_ports', [])
                for port in open_ports:
                    score = self.nist_risk_calc(
                        threat=2,
                        vulnerability=2,
                        impact=2,
                        label=f"nmap_open_port_{port}_host_{host_idx}"
                    )
                    risk += score

                vuln_list = host_data.get('vulnerabilities', [])
                for vuln_idx, vuln in enumerate(vuln_list):
                    score = self.nist_risk_calc(
                        threat=4,
                        vulnerability=4,
                        impact=4,
                        label=f"nmap_vuln_{host_idx}_{vuln_idx}_{vuln.get('id', 'unknown')}"
                    )
                    risk += score

                vulnerabilities.extend(vuln_list)

        self.details['nmap_vulnerabilities'] = vulnerabilities
        return risk

    def assess_threat_intel(self):  
        score = self.nist_risk_calc(
            threat=2,
            vulnerability=2,
            impact=2,
            label="threat_intel_simulated"
        )

        self.details['threat_intelligence'] = "Simulated threat intelligence risk: NIST-calculated"
        return score

    def assess_event_logs(self):
        risk = 0
        logs = self.data.get('event_logs', {})
        event_risk_details = {"windows": [], "linux": []}

        if logs:
            # Windows Event Logs
            if isinstance(logs, dict) and "Security" in logs:
                for idx, log in enumerate(logs.get("Security", [])):
                    if isinstance(log, dict):
                        eid = log.get("EventID")
                        if eid == 4625:
                            score = self.nist_risk_calc(
                                threat=3,
                                vulnerability=3,
                                impact=2,
                                label=f"event_windows_failed_login_{idx}_eid4625"
                            )
                            risk += score
                            event_risk_details["windows"].append(f"Failed login attempt (EventID {eid})")

                        elif eid == 1102:
                            score = self.nist_risk_calc(
                                threat=4,
                                vulnerability=4,
                                impact=4,
                                label=f"event_windows_audit_logs_cleared_{idx}_eid1102"
                            )
                            risk += score
                            event_risk_details["windows"].append("Audit logs cleared (EventID 1102)")

                        elif eid == 4688:
                            score = self.nist_risk_calc(
                                threat=2,
                                vulnerability=2,
                                impact=2,
                                label=f"event_windows_process_exec_{idx}_eid4688"
                            )
                            risk += score
                            event_risk_details["windows"].append("Process execution logged (EventID 4688)")

            # Linux Logs
            for log_type, lines in logs.items():
                if isinstance(lines, list):
                    for idx, line in enumerate(lines):
                        if "Failed password" in line:
                            score = self.nist_risk_calc(
                                threat=3,
                                vulnerability=3,
                                impact=2,
                                label=f"event_linux_failed_ssh_{log_type}_{idx}"
                            )
                            risk += score
                            event_risk_details["linux"].append("Failed SSH login detected")

                        elif "sudo" in line and "authentication failure" in line:
                            score = self.nist_risk_calc(
                                threat=2,
                                vulnerability=2,
                                impact=2,
                                label=f"event_linux_sudo_auth_failure_{log_type}_{idx}"
                            )
                            risk += score
                            event_risk_details["linux"].append("Sudo auth failure")

        self.details["event_log_flags"] = event_risk_details
        
        if "event_log_flags" in self.details:
            if self.details['event_log_flags'].get('windows') or self.details['event_log_flags'].get('linux'):
                self.recommendations.append("Investigate abnormal login attempts or cleared logs. Enable advanced auditing.")

        return risk

    def compute_risk_score(self):
    # Reset risk score to avoid accumulation on multiple runs
        self.risk_score = 0
        self.total_raw_risk_score = 0
        self.breakdown = {}

        # Accumulate NIST-normalized scores
        self.risk_score += self.assess_processes()
        self.risk_score += self.assess_network()
        self.risk_score += self.assess_digital_signatures()
        self.risk_score += self.assess_registry()
        self.risk_score += self.assess_nmap_vulnerabilities()
        self.risk_score += self.assess_threat_intel()
        self.risk_score += self.assess_event_logs()

        # Cap at 100, round off
        self.risk_score = round(min(self.risk_score, 100), 2)
        return self.risk_score

    def get_severity(self):
        if self.risk_score < 25:
            return "Low"
        elif self.risk_score < 60:
            return "Medium"
        else:
            return "High"

    def get_report(self):
        return {
            "risk_score": self.risk_score,
            "severity": self.get_severity(),
            "details": {
                **self.details,
                "risk_breakdown": self.breakdown
            },
            "recommendations": self.recommendations,
            "forensics": self.data.get('forensics', {}),
            "timestamp": datetime.datetime.now().isoformat()
        }
