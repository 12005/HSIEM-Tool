import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.dates as mdates
from datetime import datetime

import io
import matplotlib.pyplot as plt
from flask import render_template_string, Response

def create_dashboard(app, latest_report):

    @app.route("/")
    def dashboard():
        dashboard_template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>System Security Dashboard</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <style>
                body { padding: 20px; background-color: #f8f9fa; }
                .section { margin-bottom: 30px; }
                .section h2 { margin-bottom: 20px; }
                pre { background: #eee; padding: 15px; }
            </style>
        </head>
        <body>
        <div class="container">
            <div class="jumbotron text-center">
                <h1>System Security Dashboard</h1>
                <p class="lead">Overall Risk Score: <strong>{{ report.risk_score }}</strong></p>
                <p>Last Updated: {{ report.timestamp }}</p>
            </div>

            <div class="section">
                <h2>Risk Score Trend (Historical)</h2>
                <img src="/trend" class="img-fluid" alt="Risk Trend Graph">
                <h5>Last 5 Scan Results</h5>
                <table class="table table-sm">
                    <thead><tr><th>Timestamp</th><th>Risk Score</th></tr></thead>
                    <tbody>
                        {% for item in report_history %}
                        <tr><td>{{ item.timestamp }}</td><td>{{ item.risk_score }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Digital Signature Verification (Folder: test)</h2>
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
                {% else %}<p>All files in the 'test' folder have valid digital signatures.</p>{% endif %}
            </div>

            <div class="section">
                <h2>Open Ports</h2>
                {% if report.details.open_ports %}
                    <ul class="list-group">
                        {% for port in report.details.open_ports %}
                        <li class="list-group-item">{{ port }}</li>
                        {% endfor %}
                    </ul>
                {% else %}<p>No open ports detected.</p>{% endif %}
            </div>

            <div class="section">
                <h2>Registry Startup Items</h2>
                {% if report.details.registry_data and report.details.registry_data.StartupItems %}
                    <table class="table table-striped">
                        <thead><tr><th>Item</th><th>Path/Command</th></tr></thead>
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

            <div class="section">
                <h2>Suspicious Processes</h2>
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

            <div class="section">
                <h2>Nmap Vulnerability Scan Results</h2>
                {% if report.details.nmap_vulnerabilities %}
                    <table class="table table-striped">
                        <thead><tr><th>Port</th><th>Vulnerability</th><th>Details</th></tr></thead>
                        <tbody>
                            {% for vuln in report.details.nmap_vulnerabilities %}
                            <tr><td>{{ vuln.port }}</td><td>{{ vuln.script }}</td><td><pre>{{ vuln.output }}</pre></td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}<p>No vulnerabilities detected by nmap scan.</p>{% endif %}
            </div>

            <div class="section">
                <h2>Complete Report Data (JSON)</h2>
                <pre>{{ report | tojson(indent=4) }}</pre>
            </div>
        </div>
        </body>
        </html>
        '''
        return render_template_string(dashboard_template, report=latest_report)

    @app.route("/trend")
    def trend_graph():
        try:
            with open("risk_history.json", "r") as f:
                history = json.load(f)
        except Exception:
            return "No history data available."

        timestamps = [datetime.fromisoformat(item["timestamp"]) for item in history]
        scores = [item["risk_score"] for item in history]

        plt.figure(figsize=(10, 6))
        plt.plot(timestamps, scores, marker='o', linestyle='-', color='darkorange')
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M\\n%d-%m'))
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

    return app