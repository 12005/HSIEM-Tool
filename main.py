import os
import json
import threading
import schedule
import time
from flask import Flask

from collector import DataCollector
from assessment import VulnerabilityAssessment
from dashboard import create_dashboard

app = Flask(__name__)
latest_report = {}
app = create_dashboard(app, latest_report)

def run_scan():
    """Perform a full scan and update the latest report."""
    global latest_report
    collector = DataCollector()
    collected_data = collector.collect_all()
    assessment = VulnerabilityAssessment(collected_data)
    assessment.compute_risk_score()
    latest_report.update(assessment.get_report())

    with open("system_report.json", "w") as f:
        json.dump(latest_report, f, indent=4)
    print(f"Scan complete at {latest_report['timestamp']}, Risk Score: {latest_report['risk_score']}")
    
    # Append latest report to history
    history_file = "risk_history.json"
    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            history = json.load(f)
    else:
        history = []

    history.append({
        "timestamp": latest_report["timestamp"],
        "risk_score": latest_report["risk_score"]
    })

    # Keep only latest 50 entries
    history = history[-50:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=4)


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
