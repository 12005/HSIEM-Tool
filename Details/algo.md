

## **Algorithm: System Security Monitoring and Vulnerability Assessment**

### **1. Initialization**
- Import required libraries (`psutil`, `nmap`, `flask`, etc.).
- Define helper functions (e.g., `verify_digital_signature()` for checking file signatures).
- Define the `DataCollector` class to collect system data.
- Define the `VulnerabilityAssessment` class to analyze collected data and calculate a risk score.

---

### **2. Data Collection**
- `DataCollector.collect_all()`: Gathers system data using these methods:
  1. **Process Collection (`collect_processes()`)**  
     - Uses `psutil.process_iter()` to list all running processes with PID, name, and username.
  2. **Network Connection Analysis (`collect_network()`)**  
     - Uses `psutil.net_connections()` to find open network connections.
  3. **Digital Signature Verification (`verify_digital_signatures_in_test()`)**  
     - Checks if files in the `test` folder have valid digital signatures (Windows only).
  4. **Registry Audit (`audit_registry()`)**  
     - Reads Windows registry startup items (if on Windows).
  5. **Nmap Vulnerability Scan (`scan_with_nmap()`)**  
     - Runs `nmap` to find open ports and vulnerabilities.

---

### **3. Risk Assessment**
- `VulnerabilityAssessment.compute_risk_score()`: Analyzes collected data using:
  1. **Suspicious Process Detection (`assess_processes()`)**  
     - Assigns risk if process names contain malware-related keywords.
  2. **Network Risk Analysis (`assess_network()`)**  
     - Increases risk if many ports are open.
  3. **Digital Signature Check (`assess_digital_signatures()`)**  
     - Adds risk if files fail signature verification.
  4. **Registry Audit (`assess_registry()`)**  
     - Assigns risk based on startup items in Windows registry.
  5. **Nmap Vulnerability Scan (`assess_nmap_vulnerabilities()`)**  
     - Increases risk based on open ports and detected vulnerabilities.

- The **overall risk score** is computed by summing all individual risks.

---

### **4. Report Generation**
- `VulnerabilityAssessment.get_report()`: Generates a structured JSON report.
- The report includes:
  - `risk_score`: The final risk score.
  - `details`: Breakdown of risks (e.g., suspicious processes, open ports).
  - `timestamp`: When the scan was performed.

---

### **5. Web Dashboard**
- Uses **Flask** to create a dashboard displaying:
  - Risk score
  - Suspicious processes
  - Open ports
  - Failed digital signatures
  - Nmap scan results
- Generates a **graph (`/graph` route)** using `matplotlib`.

---

### **6. Automation and Scheduling**
- **Runs a scan every minute using `schedule`**.
- Uses a **background thread** to continuously check and execute scheduled scans.
- Saves reports in a `system_report.json` file.
