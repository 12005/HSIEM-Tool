from datetime import datetime
from .config_forensics import YARA_INDEX_FILE, YARA_CATEGORIES, YARA_RISK_SCORES
import hashlib
import os
import subprocess
import yara
import shutil
from elasticsearch import Elasticsearch
import mimetypes

try:
    import magic
    has_magic = True
except ImportError:
    has_magic = False


class ForensicAnalyzer:
    def __init__(self):
        self.results = {
            'file_analysis': {'status': 'Not started', 'details': 'Analysis not performed yet', 'files': {}},
            'memory_analysis': {'status': 'Not started', 'details': 'Analysis not performed yet', 'findings': {}},
            'network_forensics': {'status': 'Not started', 'details': 'Analysis not performed yet', 'connections': []},
            'disk_analysis': {'status': 'Not started', 'details': 'Analysis not performed yet', 'artifacts': {}},
            'malware_indicators': {},
            'timeline': [],
            'risk_score': 0
        }
        self.yara_rules_path = YARA_INDEX_FILE
        self.yara_categories = YARA_CATEGORIES
        self.yara_risk_scores = YARA_RISK_SCORES
        try:
            self.rules = yara.compile(filepath=self.yara_rules_path)
        except Exception as e:
            print(f"Error compiling YARA rules: {str(e)}")
            self.rules = None

    def calculate_forensic_risk(self):
        total_score = 0
        if self.results['file_analysis'].get('files'):
            total_score += len(self.results['file_analysis']['files']) * 2
        if self.results['memory_analysis'].get('findings'):
            total_score += len(self.results['memory_analysis']['findings']) * 3
        if self.results['network_forensics'].get('connections'):
            total_score += len(self.results['network_forensics']['connections']) * 1.5
        if self.results['disk_analysis'].get('artifacts'):
            total_score += len(self.results['disk_analysis']['artifacts']) * 2
        self.results['risk_score'] = min(total_score, 100)
        return self.results['risk_score']

    def analyze_files(self, directory):
        try:
            analyzed_files = {}
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    mime_type = mimetypes.guess_type(file_path)[0] or 'Unknown'
                    file_info = {
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'created': datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                        'accessed': datetime.fromtimestamp(os.path.getatime(file_path)).isoformat(),
                        'mime_type': mime_type,
                        'hash': self._calculate_file_hash(file_path),
                        'yara_matches': self.scan_file_with_yara(file_path)
                    }
                    analyzed_files[file_path] = file_info
            self.results['file_analysis']['files'] = analyzed_files
            self.results['file_analysis']['status'] = "Analysis complete"
            self.results['file_analysis']['details'] = f"Analyzed {len(analyzed_files)} files"
        except Exception as e:
            self.results['file_analysis']['status'] = "Analysis failed"
            self.results['file_analysis']['details'] = str(e)

    def analyze_memory(self, memory_dump):
        try:
            if not shutil.which("volatility3"):
                self.results['memory_analysis']['status'] = "Volatility3 not installed"
                self.results['memory_analysis']['details'] = "Volatility3 binary not found in PATH"
                return
            plugins = ['pslist', 'netscan', 'malfind', 'hivelist']
            for plugin in plugins:
                cmd = ["volatility3", "-f", memory_dump, "--plugin", plugin]
                try:
                    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
                    self.results['memory_analysis']['findings'][plugin] = output
                except Exception as e:
                    self.results['memory_analysis']['findings'][plugin] = f"Error running plugin {plugin}: {str(e)}"
            self.results['memory_analysis']['status'] = "Analysis complete"
            self.results['memory_analysis']['details'] = f"Analyzed memory dump: {memory_dump}"
        except Exception as e:
            self.results['memory_analysis']['status'] = "Analysis failed"
            self.results['memory_analysis']['details'] = str(e)

    def analyze_network_artifacts(self, pcap_file):
        self.results['network_forensics'] = {
            'connections': [],
            'status': '',
            'details': ''
        }

        try:
            if not shutil.which("tshark"):
                self.results['network_forensics']['status'] = "Tshark not installed"
                self.results['network_forensics']['details'] = "Tshark binary not found in PATH"
                return

            cmd = [
                'tshark', '-r', pcap_file, '-T', 'fields',
                '-e', 'frame.time', '-e', 'ip.src', '-e', 'ip.dst',
                '-e', 'tcp.port', '-e', 'udp.port'
            ]
            output = subprocess.check_output(cmd).decode()
            lines = output.strip().split('\n')

            for conn in lines:
                fields = conn.strip().split('\t')
                if len(fields) >= 5:
                    self.results['network_forensics']['connections'].append({
                        'time': fields[0] if fields[0] else "Unknown",
                        'src': fields[1] if fields[1] else "-",
                        'dst': fields[2] if fields[2] else "-",
                        'tcp_port': fields[3] if fields[3] else "",
                        'udp_port': fields[4] if fields[4] else ""
                    })

            self.results['network_forensics']['status'] = "Analysis complete"
            self.results['network_forensics']['details'] = f"Analyzed network capture: {pcap_file}"

        except Exception as e:
            self.results['network_forensics']['status'] = "Analysis failed"
            self.results['network_forensics']['details'] = str(e)


    def analyze_disk_artifacts(self, disk_image):
        try:
            artifacts = {}
            with open(disk_image, 'rb') as f:
                content = f.read().decode(errors='ignore').split('\n')
                for entry in content:
                    parts = entry.strip().split('|')
                    if len(parts) >= 6:
                        key = parts[0]
                        artifacts[key] = {
                            "Size": parts[1], "Created": parts[2], "Modified": parts[3],
                            "Risk": parts[4], "Indicators": parts[5]
                        }
            self.results['disk_analysis']['artifacts'] = artifacts
            self.results['disk_analysis']['status'] = "Analysis complete"
            self.results['disk_analysis']['details'] = f"Analyzed disk image: {disk_image}"
        except Exception as e:
            self.results['disk_analysis']['status'] = "Analysis failed"
            self.results['disk_analysis']['details'] = str(e)

    def _calculate_file_hash(self, file_path):
        hashes = {}
        algorithms = ['md5', 'sha1', 'sha256']
        for algo in algorithms:
            hasher = hashlib.new(algo)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            hashes[algo] = hasher.hexdigest()
        return hashes

    def scan_file_with_yara(self, file_path):
        if not self.rules:
            return {"error": "YARA rules not compiled"}
        try:
            matches = self.rules.match(file_path)
            results = []
            for match in matches:
                results.append({
                    "rule": match.rule,
                    "meta": match.meta,
                    "strings": [{"offset": s[0], "identifier": s[1], "data": s[2]} for s in match.strings],
                    "tags": match.tags
                })
            return results
        except Exception as e:
            return {"error": f"YARA scan failed: {str(e)}"}

    def analyze_all(self, target_dir=None):
        try:
            if not target_dir:
                target_dir = os.path.join(os.getcwd(), "test")
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir)
            self.analyze_files(target_dir)
            mem_path = os.path.join(target_dir, "memory.dmp")
            if os.path.exists(mem_path):
                self.analyze_memory(mem_path)
            net_path = os.path.join(target_dir, "capture.pcap")
            if os.path.exists(net_path):
                self.analyze_network_artifacts(net_path)
            disk_path = os.path.join(target_dir, "disk.img")
            if os.path.exists(disk_path):
                self.analyze_disk_artifacts(disk_path)
            self.calculate_forensic_risk()
            return self.results
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}", "timestamp": datetime.now().isoformat()}
