import os
import psutil
import platform
import subprocess
import nmap

from utils import verify_digital_signature

if platform.system() == "Windows":
    import winreg
else:
    winreg = None

class DataCollector:
    def __init__(self):
        self.data = {}
        self.nm = nmap.PortScanner()

    def collect_processes(self):
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_list.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self.data['processes'] = process_list
        return process_list

    def collect_network(self):
        connections = []
        for conn in psutil.net_connections():
            try:
                conn_info = {
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status
                }
                connections.append(conn_info)
            except Exception:
                continue
        self.data['network_connections'] = connections
        return connections

    def verify_digital_signatures_in_test(self):
        results = []
        test_folder = os.path.join(os.getcwd(), "test")
        if not os.path.exists(test_folder):
            results.append({"error": f"Folder {test_folder} does not exist."})
        else:
            for filename in os.listdir(test_folder):
                file_path = os.path.join(test_folder, filename)
                if os.path.isfile(file_path):
                    result = verify_digital_signature(file_path)
                    results.append(result)
        self.data['digital_signatures'] = results
        return results

    def audit_registry(self):
        registry_data = {}
        if winreg is None:
            return {"error": "Registry auditing is only available on Windows."}
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
            values = {}
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = value
                    i += 1
                except OSError:
                    break
            registry_data["StartupItems"] = values
        except Exception as e:
            registry_data["error"] = str(e)
        self.data['registry'] = registry_data
        return registry_data

    def scan_with_nmap(self):
        try:
            self.nm.scan('127.0.0.1', arguments='-sV -sC --script vuln')
            scan_results = []
            for host in self.nm.all_hosts():
                host_data = {
                    'host': host,
                    'state': self.nm[host].state(),
                    'vulnerabilities': [],
                    'open_ports': []
                }
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        host_data['open_ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', '')
                        })
                        if 'script' in port_info:
                            for script_name, output in port_info['script'].items():
                                if 'VULNERABLE' in output or 'CVE-' in output:
                                    host_data['vulnerabilities'].append({
                                        'port': port,
                                        'script': script_name,
                                        'output': output
                                    })
                scan_results.append(host_data)
            self.data['nmap_scan'] = scan_results
            return scan_results
        except Exception as e:
            self.data['nmap_scan'] = {'error': str(e)}
            return {'error': str(e)}

    def collect_all(self):
        self.collect_processes()
        self.collect_network()
        self.verify_digital_signatures_in_test()
        self.scan_with_nmap()
        if platform.system() == "Windows":
            self.audit_registry()
        return self.data