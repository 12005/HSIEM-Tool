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
            <h2 class="mb-4"><i class="fas fa-calculator"></i> Risk Score Breakdown</h2>
            <p class="text-muted">Based on <strong>NIST SP 800-30</strong> model: <code>Risk = Threat × Vulnerability × Impact</code></p>
            <div class="card shadow-sm border-0">
                <div class="card-body">
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <strong>Suspicious Processes:</strong>
                            <span class="badge badge-secondary">{{ report.details.suspicious_processes | length }}</span>
                            (Scored using high Threat × high Vulnerability × medium Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Abnormal Behavior Flags:</strong>
                            <span class="badge badge-secondary">{{ report.details.behavioral_flags | length }}</span>
                            (Scored using medium Threat × medium Vulnerability × low Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Unusual High Ports:</strong>
                            <span class="badge badge-secondary">{{ report.details.unusual_ports | length }}</span>
                            (Scored using medium Threat × medium Vulnerability × medium Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Excessive Open Ports:</strong>
                            {{ report.details.open_ports | length }} open {% if report.details.open_ports | length > 10 %} → High Risk{% else %}(low risk){% endif %}
                        </li>
                        <li class="list-group-item">
                            <strong>Failed Digital Signatures:</strong>
                            <span class="badge badge-secondary">{{ report.details.failed_digital_signatures | length }}</span>
                            (Scored using low Threat × high Vulnerability × medium Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Unknown Registry Entries:</strong>
                            <span class="badge badge-secondary">{{ report.details.unknown_startup_items | length }}</span>
                            (Scored using medium Threat × medium Vulnerability × medium Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Nmap Vulnerabilities:</strong>
                            <span class="badge badge-secondary">{{ report.details.nmap_vulnerabilities | length }}</span>
                            (Scored using high Threat × high Vulnerability × high Impact)
                        </li>
                        <li class="list-group-item">
                            <strong>Event Log Flags:</strong>
                            {% if report.details.event_log_flags.windows or report.details.event_log_flags.linux %}
                                Dynamic risk from system events (e.g., Failed Logins, Audit Log Clears)
                            {% else %}
                                No impact
                            {% endif %}
                        </li>
                        <li class="list-group-item">
                            <strong>Threat Intelligence:</strong>
                            (Baseline threat score based on simulated intel)
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

            <!-- TABS START -->
            <ul class="nav nav-tabs" id="reportTabs" role="tablist">
                <li class="nav-item"><a class="nav-link active" data-toggle="tab" href="#processes">Suspicious Processes</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#ports">Open Ports</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#signatures">Digital Signatures</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#registry">Registry Items</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#nmap">Nmap Vulnerabilities</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#logs">Event Logs</a></li>
                <li class="nav-item"><a class="nav-link" data-toggle="tab" href="#json">Complete JSON Report</a></li>
            </ul>

            <div class="tab-content mt-4">
                <!-- Processes -->
                <div id="processes" class="tab-pane container active">
                    {% if report.details.suspicious_processes %}
                        <table class="table table-striped">
                            <thead><tr><th>PID</th><th>Name</th><th>User</th></tr></thead>
                            <tbody>
                                {% for proc in report.details.suspicious_processes %}
                                <tr><td>{{ proc.pid }}</td><td>{{ proc.name }}</td><td>{{ proc.username }}</td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}<p>No suspicious processes detected.</p>{% endif %}
                </div>

                <!-- Ports -->
                <div id="ports" class="tab-pane container fade">
                    {% if report.details.open_ports %}
                        <ul class="list-group">
                            {% for port in report.details.open_ports %}
                            <li class="list-group-item">{{ port }}</li>
                            {% endfor %}
                        </ul>
                    {% else %}<p>No open ports detected.</p>{% endif %}
                </div>

                <!-- Signatures -->
                <div id="signatures" class="tab-pane container fade">
                    {% if report.details.failed_digital_signatures %}
                        <table class="table table-striped">
                            <thead><tr><th>File</th><th>Status</th><th>Output/Error</th></tr></thead>
                            <tbody>
                                {% for sig in report.details.failed_digital_signatures %}
                                <tr>
                                    <td>{{ sig.file }}</td>
                                    <td>{% if sig.signature_valid %}Valid{% else %}Invalid{% endif %}</td>
                                    <td>{% if sig.error %}{{ sig.error }}{% else %}{{ sig.output }}{% endif %}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}<p>All digital signatures are valid.</p>{% endif %}
                </div>

                <!-- Registry -->
                <div id="registry" class="tab-pane container fade">
                    {% if report.details.registry_data and report.details.registry_data.StartupItems %}
                        <table class="table table-striped">
                            <thead><tr><th>Item</th><th>Command</th></tr></thead>
                            <tbody>
                                {% for key, value in report.details.registry_data.StartupItems.items() %}
                                <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% elif report.details.registry_data.error %}
                        <p>Error auditing registry: {{ report.details.registry_data.error }}</p>
                    {% else %}<p>No registry startup items found.</p>{% endif %}
                </div>

                <!-- Nmap -->
                <div id="nmap" class="tab-pane container fade">
                    {% if report.details.nmap_vulnerabilities %}
                        <table class="table table-striped">
                            <thead><tr><th>Port</th><th>Vulnerability</th><th>Details</th></tr></thead>
                            <tbody>
                                {% for vuln in report.details.nmap_vulnerabilities %}
                                <tr><td>{{ vuln.port }}</td><td>{{ vuln.script }}</td><td><pre>{{ vuln.output }}</pre></td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}<p>No Nmap vulnerabilities detected.</p>{% endif %}
                </div>
                
                <!-- Event Log Analysis -->
                <div id="logs" class="tab-pane container fade">
                    {% if report.details.event_logs %}
                        {% for log_type, entries in report.details.event_logs.items() %}
                            <h5 class="mt-3">{{ log_type }}</h5>
                            {% if entries %}
                                <pre style="background:#f1f1f1; padding:10px; max-height:300px; overflow:auto;">
                                    {% for entry in entries %}
                                        {{ entry }}
                                    {% endfor %}
                                </pre>
                            {% else %}
                                <p>No entries found for {{ log_type }}.</p>
                            {% endif %}
                        {% endfor %}
                    {% else %}
                        <p>No event logs available.</p>
                    {% endif %}
                </div>
                
                <!-- JSON -->
                <div id="json" class="tab-pane container fade">
                    <pre>{{ report | tojson(indent=4) }}</pre>
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
        labels = ['Processes', 'Network', 'Digital Signatures', 'Registry', 'Threat Intel']
        details = latest_report.get("details", {})
        process_risk = len(details.get("suspicious_processes", [])) * 5
        network_risk = 3 if len(details.get("open_ports", [])) > 10 else 1
        ds_risk = len(details.get("failed_digital_signatures", [])) * 2
        registry_info = details.get("registry_data", {})
        registry_risk = 2 if ("error" in registry_info or len(registry_info.get("StartupItems", {})) > 5) else 0
        threat_risk = 1
        values = [process_risk, network_risk, ds_risk, registry_risk, threat_risk]

        plt.figure(figsize=(8, 6))
        plt.bar(labels, values, color='steelblue')
        plt.ylabel("Risk Score")
        plt.title("Risk Components")
        buf = io.BytesIO()
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
