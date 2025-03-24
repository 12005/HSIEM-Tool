import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import render_template_string, Response
import json

def create_dashboard(app, latest_report):

    @app.route("/")
    def dashboard():
        try:
            with open("risk_history.json", "r") as f:
                report_history = json.load(f)[-5:]
        except Exception:
            report_history = []

        dashboard_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>System Security Dashboard</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

            <style>
                body { padding: 20px; background-color: #f8f9fa; }
                .section { margin-bottom: 30px; }
                .section h2 { margin-bottom: 20px; }
                pre { background: #eee; padding: 15px; }
            </style>
        </head>
        <body>
        <!-- START: Dashboard HTML Template Update --> 
        <div class="container">
            <div class="jumbotron text-center">
                <h1>System Security Dashboard</h1>
                <p class="lead">Overall Risk Score: <strong>{{ report.risk_score }}</strong> ({{ report.severity }})</p>
                <p>Last Updated: {{ report.timestamp }}</p>
            </div>

           <div class="section">
            <h2 class="mb-4"><i class="fas fa-shield-alt"></i> Security Risk Assessment</h2>
            <div class="card shadow-sm border-0">
                <div class="card-body">
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Process Analysis</strong>
                                <p class="mb-0 text-muted small">Assessment of suspicious processes and behaviors</p>
                            </div>
                            <span class="badge badge-pill badge-primary">{{ report.details.suspicious_processes | length if report.details.suspicious_processes else 0 }} detected</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Network Security</strong>
                                <p class="mb-0 text-muted small">Analysis of ports and network vulnerabilities</p>
                            </div>
                            <span class="badge badge-pill badge-primary">{{ report.details.open_ports | length if report.details.open_ports else 0 }} open ports</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Digital Signature Verification</strong>
                                <p class="mb-0 text-muted small">Validation of file signatures and certificates</p>
                            </div>
                            <span class="badge badge-pill badge-danger">{{ report.details.failed_digital_signatures | length if report.details.failed_digital_signatures else 0 }} failed</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Registry Analysis</strong>
                                <p class="mb-0 text-muted small">Detection of unknown startup items</p>
                            </div>
                            <span class="badge badge-pill badge-warning">{{ report.details.unknown_startup_items | length if report.details.unknown_startup_items else 0 }} unknown</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Vulnerability Scan</strong>
                                <p class="mb-0 text-muted small">Nmap security assessment results</p>
                            </div>
                            <span class="badge badge-pill badge-danger">{{ report.details.nmap_vulnerabilities | length if report.details.nmap_vulnerabilities else 0 }} found</span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Event Log Analysis</strong>
                                <p class="mb-0 text-muted small">System event anomalies and security alerts</p>
                            </div>
                            <span class="badge badge-pill badge-info">
                                {% if report.details.event_log_flags and (report.details.event_log_flags.get('windows') or report.details.event_log_flags.get('linux')) %}
                                    Active Alerts
                                {% else %}
                                    No Alerts
                                {% endif %}
                            </span>
                        </li>
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>Threat Intelligence</strong>
                                <p class="mb-0 text-muted small">External threat data correlation</p>
                            </div>
                            <span class="badge badge-pill badge-secondary">Active Monitoring</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        
            <div class="section">
                <h2>Risk Score Trend (Historical)</h2>
                <img src="/trend" class="img-fluid" alt="Risk Trend Graph">
                <h5 class="mt-4">Last 5 Scan Results</h5>
                <table class="table table-sm">
                    <thead><tr><th>Timestamp</th><th>Risk Score</th></tr></thead>
                    <tbody>
                        {% for item in report_history %}
                        <tr><td>{{ item.timestamp }}</td><td>{{ item.risk_score }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div class="section mt-5">
                <h2 class="mb-4"><i class="fas fa-lightbulb"></i> How to Reduce Your Risk</h2>
                <div class="card shadow-sm border-0">
                    <div class="card-body">
                        {% if report.recommendations and report.recommendations|length > 0 %}
                            <ul class="list-group">
                                {% for rec in report.recommendations %}
                                    <li class="list-group-item">
                                        <i class="fas fa-check-circle text-success"></i> {{ rec }}
                                    </li>
                                {% endfor %}
                            </ul>
                        {% else %}
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle"></i> No high-risk areas detected. Your system looks good!
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>

            <!-- TABS START -->
            <ul class="nav nav-tabs" id="reportTabs" role="tablist">
                <li class="nav-item"><a class="nav-link active" data-toggle="tab" href="#processes">Suspicious Processes</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#ports">Network Analysis</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#signatures">Digital Signatures</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#registry">Registry Items</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#nmap">Vulnerabilities</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#logs">Event Logs</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#forensics">Forensics</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#json">Full Report</a></li>
            </ul>

            <div class="tab-content mt-4">
                <!-- Processes -->
                <div id="processes" class="tab-pane container active">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Displaying processes that exhibit suspicious behavior or unusual patterns.
                    </div>
                    {% if report.details.suspicious_processes %}
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="thead-light">
                                    <tr>
                                        <th>PID</th>
                                        <th>Process Name</th>
                                        <th>User</th>
                                        <th>CPU Usage</th>
                                        <th>Memory Usage</th>
                                        <th>Start Time</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for proc in report.details.suspicious_processes %}
                                    <tr>
                                        <td><code>{{ proc.pid }}</code></td>
                                        <td>
                                            <strong>{{ proc.name }}</strong>
                                            {% if proc.path %}<br><small class="text-muted">{{ proc.path }}</small>{% endif %}
                                        </td>
                                        <td>{{ proc.username }}</td>
                                        <td>{{ proc.cpu_percent }}%</td>
                                        <td>{{ proc.memory_usage }}</td>
                                        <td>{{ proc.create_time }}</td>
                                        <td>
                                            <span class="badge badge-{{ proc.risk_level | lower }}">
                                                {{ proc.risk_level }}
                                            </span>
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% else %}
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> No suspicious processes detected.
                        </div>
                    {% endif %}
                </div>

                <!-- Network Analysis -->
                <div id="ports" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Network port analysis and potential security implications.
                    </div>
                    {% if report.details.open_ports %}
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-door-open"></i> Open Ports</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-sm">
                                                <thead>
                                                    <tr>
                                                        <th>Port</th>
                                                        <th>Service</th>
                                                        <th>State</th>
                                                        <th>Risk Level</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {% for port in report.details.open_ports %}
                                                    <tr>
                                                        <td><code>{{ port.number }}</code></td>
                                                        <td>{{ port.service }}</td>
                                                        <td>{{ port.state }}</td>
                                                        <td>
                                                            <span class="badge badge-{{ port.risk | lower }}">
                                                                {{ port.risk }}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                    {% endfor %}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-exclamation-triangle"></i> Unusual Port Activity</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-sm">
                                                <thead>
                                                    <tr>
                                                        <th>Port</th>
                                                        <th>Anomaly Type</th>
                                                        <th>Details</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {% for port in report.details.open_ports %}
                                                    <tr>
                                                        <td><code>{{ port.number }}</code></td>
                                                        <td>{{ port.service }}</td>
                                                        <td>{{ port.state }}</td>
                                                        <td>
                                                            <span class="badge badge-{{ port.risk | lower }}">
                                                                {{ port.risk }}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                    {% endfor %}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    {% else %}
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> No concerning port activity detected.
                        </div>
                    {% endif %}
                </div>

                <!-- Digital Signatures -->
                <div id="signatures" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Digital signature verification results for system files and applications.
                    </div>
                    {% if report.details.failed_digital_signatures %}
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="thead-light">
                                    <tr>
                                        <th>File Path</th>
                                        <th>Signature Status</th>
                                        <th>Certificate Info</th>
                                        <th>Timestamp</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for sig in report.details.failed_digital_signatures %}
                                    <tr class="{% if not sig.signature_valid %}table-danger{% endif %}">
                                        <td>
                                            <code>{{ sig.file }}</code>
                                            {% if sig.file_hash %}<br>
                                            <small class="text-muted">SHA256: {{ sig.file_hash }}</small>
                                            {% endif %}
                                        </td>
                                        <td>
                                            <span class="badge badge-{{ 'success' if sig.signature_valid else 'danger' }}">
                                                {{ 'Valid' if sig.signature_valid else 'Invalid' }}
                                            </span>
                                        </td>
                                        <td>
                                            {% if sig.cert_info %}
                                                Issuer: {{ sig.cert_info.issuer }}<br>
                                                Expires: {{ sig.cert_info.expiry }}
                                            {% else %}
                                                <em>No certificate information</em>
                                            {% endif %}
                                        </td>
                                        <td>{{ sig.timestamp }}</td>
                                        <td>
                                            {% if sig.error %}
                                                <span class="text-danger">{{ sig.error }}</span>
                                            {% else %}
                                                {{ sig.output }}
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% else %}
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> All digital signatures are valid.
                        </div>
                    {% endif %}
                </div>

                <!-- Registry -->
                <div id="registry" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Analysis of system registry and startup configurations.
                    </div>
                    {% if report.details.registry_anomalies is defined and report.details.registry_anomalies %}
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-play-circle"></i> Startup Items</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="table-responsive">
                                            <table class="table table-hover">
                                                <thead>
                                                    <tr>
                                                        <th>Item Name</th>
                                                        <th>Command</th>
                                                        <th>Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {% for key, value in report.details.registry_data.StartupItems.items() %}
                                                    <tr>
                                                        <td>{{ key }}</td>
                                                        <td><code>{{ value }}</code></td>
                                                        <td>
                                                            <span class="badge badge-{{ 'success' if key in report.details.known_safe_items else 'warning' }}">
                                                                {{ 'Known Safe' if key in report.details.known_safe_items else 'Unknown' }}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                    {% endfor %}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-exclamation-circle"></i> Registry Anomalies</h5>
                                    </div>
                                    <div class="card-body">
                                        {% if report.details.registry_anomalies %}
                                            <ul class="list-group">
                                                {% for anomaly in report.details.registry_anomalies %}
                                                <li class="list-group-item">
                                                    <h6>{{ anomaly.type }}</h6>
                                                    <code>{{ anomaly.path }}</code>
                                                    <p class="mb-0 text-muted">{{ anomaly.description }}</p>
                                                </li>
                                                {% endfor %}
                                            </ul>
                                        {% else %}
                                            <p class="text-success mb-0">No registry anomalies detected.</p>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>
                        </div>
                    {% else %}
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> Unable to access registry data: {{ report.details.registry_data.error }}
                        </div>
                    {% endif %}
                </div>

                <!-- Vulnerabilities -->
                <div id="nmap" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Detailed vulnerability scan results and security findings.
                    </div>
                    {% if report.details.nmap_vulnerabilities %}
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="thead-light">
                                    <tr>
                                        <th>Port/Service</th>
                                        <th>Vulnerability</th>
                                        <th>Severity</th>
                                        <th>Details</th>
                                        <th>Recommendations</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for vuln in report.details.nmap_vulnerabilities %}
                                    <tr class="table-{{ vuln.severity | lower }}">
                                        <td>
                                            <strong>{{ vuln.port }}</strong><br>
                                            <small class="text-muted">{{ vuln.service }}</small>
                                        </td>
                                        <td>{{ vuln.script }}</td>
                                        <td>
                                            <span class="badge badge-{{ vuln.severity | lower }}">
                                                {{ vuln.severity }}
                                            </span>
                                        </td>
                                        <td>
                                            <pre class="mb-0"><code>{{ vuln.output }}</code></pre>
                                        </td>
                                        <td>{{ vuln.recommendation }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% else %}
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i> No vulnerabilities detected in the Nmap scan.
                        </div>
                    {% endif %}
                </div>

                <!-- Event Logs -->
                <div id="logs" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> System event logs and security-related events.
                    </div>
                    {% if report.details.event_logs %}
                        {% if "error" in report.details.event_logs %}
                            <div class="alert alert-warning">
                                <i class="fas fa-exclamation-triangle"></i> {{ report.details.event_logs.error }}
                                {% if report.details.event_logs.requires_admin %}
                                    <br><strong>Solution:</strong> Run the application with administrative privileges.
                                {% endif %}
                            </div>
                        {% else %}
                            {% for log_type, entries in report.details.event_logs.items() %}
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0">
                                            <i class="fas fa-file-alt"></i> {{ log_type }}
                                        </h5>
                                    </div>
                                    <div class="card-body">
                                        {% if entries %}
                                            <div class="table-responsive">
                                                <table class="table table-sm">
                                                    <thead>
                                                        <tr>
                                                            <th>Timestamp</th>
                                                            <th>Event ID</th>
                                                            <th>Level</th>
                                                            <th>Source</th>
                                                            <th>Message</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {% for entry in entries %}
                                                        <tr class="{% if entry.level in ['Error', 'Critical'] %}table-danger{% elif entry.level == 'Warning' %}table-warning{% endif %}">
                                                            <td>{{ entry.timestamp }}</td>
                                                            <td><code>{{ entry.event_id }}</code></td>
                                                            <td>
                                                                <span class="badge badge-{{ entry.level | lower }}">
                                                                    {{ entry.level }}
                                                                </span>
                                                            </td>
                                                            <td>{{ entry.source }}</td>
                                                            <td>{{ entry.message }}</td>
                                                        </tr>
                                                        {% endfor %}
                                                    </tbody>
                                                </table>
                                            </div>
                                        {% else %}
                                            <p class="mb-0">No entries found for {{ log_type }}.</p>
                                        {% endif %}
                                    </div>
                                </div>
                            {% endfor %}
                        {% endif %}
                    {% else %}
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> No event logs available. This might be due to:
                            <ul class="mt-2">
                                <li>Insufficient permissions (try running as administrator)</li>
                                <li>Event logging service not running</li>
                                <li>Log files not accessible</li>
                            </ul>
                        </div>
                    {% endif %}
                </div>

                <!-- Forensics Tab -->
                <div id="forensics" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-search"></i> Forensic analysis results and findings.
                    </div>
                    {% if report.get('forensics') %}
                        <div class="row">
                            <!-- File Analysis -->
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-file"></i> File Analysis</h5>
                                    </div>
                                    <div class="card-body">
                                        {% if report.forensics.get('file_analysis') %}
                                            <div class="table-responsive">
                                                <table class="table table-sm">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Details</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <tr>
                                                            <td>{{ report.forensics.file_analysis.status }}</td>
                                                            <td>{{ report.forensics.file_analysis.details }}</td>
                                                        </tr>
                                                    </tbody>
                                                </table>
                                                {% if report.forensics.file_analysis.files %}
                                                <hr>
                                                <h6>Analyzed Files:</h6>
                                                <div class="table-responsive">
                                                <table class="table table-sm table-bordered">
                                                    <thead>
                                                    <tr>
                                                        <th>File Path</th>
                                                        <th>Size</th>
                                                        <th>Created</th>
                                                        <th>Modified</th>
                                                        <th>Accessed</th>
                                                        <th>Mime Type</th>
                                                        <th>Hashes</th>
                                                        <th>YARA Matches</th>
                                                    </tr>
                                                    </thead>
                                                    <tbody>
                                                    {% for path, file in report.forensics.file_analysis.files.items() %}
                                                    <tr>
                                                        <td><code>{{ path }}</code></td>
                                                        <td>{{ file.size }}</td>
                                                        <td>{{ file.created }}</td>
                                                        <td>{{ file.modified }}</td>
                                                        <td>{{ file.accessed }}</td>
                                                        <td>{{ file.mime_type }}</td>
                                                        <td>
                                                        {% for algo, h in file.hash.items() %}
                                                            <strong>{{ algo|upper }}</strong>: {{ h }}<br>
                                                        {% endfor %}
                                                        </td>
                                                        <td>
                                                        {% if file.yara_matches and file.yara_matches|length > 0 %}
                                                            <ul>
                                                            {% for match in file.yara_matches %}
                                                                <li><strong>{{ match.rule }}</strong> - Tags: {{ match.tags|join(', ') }}</li>
                                                            {% endfor %}
                                                            </ul>
                                                        {% else %}
                                                            <span class="text-success">No matches</span>
                                                        {% endif %}
                                                        </td>
                                                    </tr>
                                                    {% endfor %}
                                                    </tbody>
                                                </table>
                                                </div>
                                                {% endif %}
                                            </div>
                                        {% else %}
                                            <p class="text-muted">No file analysis data available.</p>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>

                            <!-- Memory Analysis -->
                            <div class="col-md-6">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-memory"></i> Memory Analysis</h5>
                                    </div>
                                    <div class="card-body">
                                        {% if report.forensics.get('memory_analysis') %}
                                            <div class="table-responsive">
                                                <table class="table table-sm">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Details</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <tr>
                                                            <td>{{ report.forensics.memory_analysis.status }}</td>
                                                            <td>{{ report.forensics.memory_analysis.details }}</td>
                                                        </tr>
                                                    </tbody>
                                                </table>
                                                {% if report.forensics.memory_analysis.findings %}
                                                <hr>
                                                <h6>Volatility Plugin Results:</h6>
                                                {% for plugin, result in report.forensics.memory_analysis.findings.items() %}
                                                <h6>{{ plugin }}</h6>
                                                <pre>{{ result }}</pre>
                                                {% endfor %}
                                                {% endif %}
                                            </div>
                                        {% else %}
                                            <p class="text-muted">No memory analysis data available.</p>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>

                            <!-- Network Forensics -->
                            <div class="col-md-12">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-network-wired"></i> Network Forensics</h5>
                                    </div>
                                    <div class="card-body">
                                        {% if report.forensics.get('network_forensics') %}
                                            <div class="table-responsive">
                                                <table class="table table-sm">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Details</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <tr>
                                                            <td>{{ report.forensics.network_forensics.status }}</td>
                                                            <td>{{ report.forensics.network_forensics.details }}</td>
                                                            
                                                        </tr>
                                                    </tbody>
                                                </table>
                                                {% if report.forensics.network_forensics.connections %}
                                                <hr>
                                                <h6>PCAP Connections:</h6>
                                                <div class="table-responsive">
                                                <table class="table table-sm table-bordered">
                                                    <thead>
                                                    <tr>
                                                        <th>Time</th>
                                                        <th>Source IP</th>
                                                        <th>Destination IP</th>
                                                        <th>TCP Port</th>
                                                        <th>UDP Port</th>
                                                    </tr>
                                                    </thead>
                                                    <tbody>
                                                    {% for conn in report.forensics.network_forensics.connections %}
                                                    <tr>
                                                        <td>{{ conn.time }}</td>
                                                        <td>{{ conn.src }}</td>
                                                        <td>{{ conn.dst }}</td>
                                                        <td>{{ conn.tcp_port }}</td>
                                                        <td>{{ conn.udp_port }}</td>
                                                    </tr>
                                                    {% endfor %}
                                                    </tbody>
                                                </table>
                                                </div>
                                                {% endif %}
                                            </div>
                                        {% else %}
                                            <p class="text-muted">No network forensics data available.</p>
                                        {% endif %}
                                    </div>
                                </div>
                            </div>

                            <!-- Disk Analysis -->
                            <div class="col-md-12">
                                <div class="card mb-3">
                                    <div class="card-header">
                                        <h5 class="mb-0"><i class="fas fa-hdd"></i> Disk Analysis</h5>
                                    </div>
                                    <div class="card-body">
                                        {% if report.forensics.get('disk_analysis') %}
                                            <div class="table-responsive">
                                                <table class="table table-sm">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Details</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <tr>
                                                            <td>{{ report.forensics.disk_analysis.status }}</td>
                                                            <td>{{ report.forensics.disk_analysis.details }}</td>
                                                            
                                                        </tr>
                                                    </tbody>
                                                </table>
                                                {% if report.forensics.disk_analysis.artifacts %}
                                                <hr>
                                                <h6>Disk Artifacts:</h6>
                                                <ul class="list-group">
                                                {% for key, value in report.forensics.disk_analysis.artifacts.items() %}
                                                <li class="list-group-item"><strong>{{ key }}</strong>: {{ value }}</li>
                                                {% endfor %}
                                                </ul>
                                                {% endif %}
                                                </div>
                                            {% else %}
                                                <p class="text-muted">No disk analysis data available.</p>
                                            {% endif %}
                                    </div>
                                </div>
                            </div>
                        </div>
                    {% else %}
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle"></i> No forensics data available.
                        </div>
                    {% endif %}
                </div>

                <!-- Full Report -->
                <div id="json" class="tab-pane container fade">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Complete scan report in JSON format.
                    </div>
                    <div class="card">
                        <div class="card-body">
                            <pre class="mb-0"><code class="json">{{ report | tojson(indent=4) }}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
            <!-- TABS END -->
        </div>

        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>

        </body>
        </html>
        '''
        return render_template_string(dashboard_template, report=latest_report, report_history=report_history)

    @app.route("/graph")
    def graph():
        from collections import defaultdict

        breakdown = latest_report.get("details", {}).get("risk_breakdown", {})
        category_scores = defaultdict(float)

        # Categorize each breakdown label and sum scores dynamically
        for label, item in breakdown.items():
            score = item.get("normalized_score", 0)

            if "proc_" in label:
                category_scores["Processes"] += score
            elif "network_" in label:
                category_scores["Network"] += score
            elif "signature_invalid" in label:
                category_scores["Digital Signatures"] += score
            elif "registry_" in label:
                category_scores["Registry"] += score
            elif "nmap_" in label:
                category_scores["Nmap Scan"] += score
            elif "event_" in label:
                category_scores["Event Logs"] += score
            elif "threat_intel" in label:
                category_scores["Threat Intel"] += score
            else:
                category_scores["Other"] += score

        labels = list(category_scores.keys())
        values = list(category_scores.values())

        # Plot
        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, values, color='darkorange')
        plt.ylabel("Normalized Risk Score")
        plt.title("Dynamic Risk Composition by Category")
        plt.xticks(rotation=30)
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2.0, height + 0.5, f"{height:.2f}", ha='center')

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png')
        buf.seek(0)
        plt.close()
        return Response(buf.getvalue(), mimetype='image/png')

    @app.route("/trend")
    def trend_graph():
        import matplotlib.dates as mdates
        from datetime import datetime

        try:
            with open("risk_history.json", "r") as f:
                history = json.load(f)
        except Exception:
            return "No history data available."

        timestamps = [datetime.fromisoformat(item["timestamp"]) for item in history]
        scores = [item["risk_score"] for item in history]

        plt.figure(figsize=(10, 6))
        plt.plot(timestamps, scores, marker='o', linestyle='-', color='darkorange')
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M\n%d-%m'))
        plt.gcf().autofmt_xdate()
        plt.title("Risk Score Trend Over Time")
        plt.xlabel("Timestamp")
        plt.ylabel("Risk Score")
        plt.grid(True)

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        plt.close()
        return Response(buf.getvalue(), mimetype='image/png')

    return app
