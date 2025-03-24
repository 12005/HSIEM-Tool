import os
import json
import threading
import schedule
import time
import datetime
from flask import Flask

from collector import DataCollector
from assessment import VulnerabilityAssessment
from forensics.forensic_analyzer import ForensicAnalyzer
from dashboard import create_dashboard

app = Flask(__name__)
latest_report = {}
app = create_dashboard(app, latest_report)

def run_scan():
    """Perform a full scan and update the latest report."""
    global latest_report
    collector = DataCollector()
    collector = DataCollector()
    try:
        collected_data = collector.collect_all()
    except Exception as e:
        print("[!] Data Collection Error:", str(e))
        collected_data = {"error": "Failed to collect system data", "exception": str(e)}

    
    # Add forensic analysis
    print("Starting forensic analysis...")
    try:
        forensic_analyzer = ForensicAnalyzer()
        forensic_results = forensic_analyzer.analyze_all()
    except Exception as e:
        print("[!] Forensic Analysis Error:", str(e))
        forensic_results = {
            "status": "Forensic analysis failed",
            "error": str(e)
        }

    print("Forensic analysis results:", json.dumps(forensic_results, indent=2))
    
    # Update risk score from forensics
    if 'risk_score' in forensic_results:
        collected_data['forensic_risk_score'] = forensic_results['risk_score']
    
    collected_data['forensics'] = forensic_results
    try:
        assessment = VulnerabilityAssessment(collected_data)
        assessment.compute_risk_score()
        latest_report.update(assessment.get_report())
    except Exception as e:
        print("[!] Assessment Error:", str(e))
        latest_report.update({
            "risk_score": -1,
            "severity": "Error",
            "details": {"error": str(e)},
            "timestamp": datetime.datetime.now().isoformat()
        })

    try:
        with open("system_report.json", "w") as f:
            json.dump(latest_report, f, indent=4)
    except Exception as e:
        print("[!] Failed to save system_report.json:", str(e))
    print(f"Scan complete at {latest_report['timestamp']}, Risk Score: {latest_report['risk_score']}")
    
    # Append latest report to history
    history_file = "risk_history.json"
    try:
        if os.path.exists(history_file):
            with open(history_file, "r") as f:
                history = json.load(f)
        else:
            history = []
        history.append({
            "timestamp": latest_report["timestamp"],
            "risk_score": latest_report["risk_score"]
        })
        history = history[-50:]
        with open(history_file, "w") as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        print("[!] Failed to update risk history:", str(e))

def scheduled_scan():
    run_scan()

if __name__ == "__main__":
    schedule.every(1).minutes.do(scheduled_scan)
    run_scan()

    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    app.run(host="0.0.0.0", port=5000)
