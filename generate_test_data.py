# generate_test_data.py
import os
import random
import string

TEST_DIR = os.path.join(os.getcwd(), 'test')
os.makedirs(TEST_DIR, exist_ok=True)

# 1️⃣ Generate sample files for file analysis
sample_file_paths = []
for i in range(3):
    filename = f"suspicious_file_{i}.txt"
    file_path = os.path.join(TEST_DIR, filename)
    with open(file_path, 'w') as f:
        f.write("This file contains a suspicious keyword: malware\n")
    sample_file_paths.append(file_path)

# 2️⃣ Generate a dummy memory.dmp file
memory_dump_path = os.path.join(TEST_DIR, "memory.dmp")
with open(memory_dump_path, 'w') as f:
    for i in range(10):
        f.write(f"Process: {random.randint(1000,9999)} | Keyword: injected | PID: {random.randint(2000,9999)}\n")

# 3️⃣ Generate a dummy capture.pcap file with sample lines (pretend tshark fields)
pcap_path = os.path.join(TEST_DIR, "capture.pcap")
with open(pcap_path, 'w') as f:
    f.write("2025-03-19 10:10:10\t192.168.1.2\t10.0.0.5\t80\t-\n")
    f.write("2025-03-19 10:11:12\t192.168.1.3\t10.0.0.8\t443\t-\n")
    f.write("2025-03-19 10:12:15\t10.0.0.5\t192.168.1.2\t-\t53\n")

# 4️⃣ Generate a dummy disk.img file with entries in expected format
# Format: key|size|created|modified|risk|indicators
disk_image_path = os.path.join(TEST_DIR, "disk.img")
with open(disk_image_path, 'w') as f:
    f.write("System32.dll|512KB|2023-01-01|2023-01-02|High|Suspicious DLL injection\n")
    f.write("autorun.inf|5KB|2022-12-25|2022-12-26|Medium|Auto-execution setup\n")
    f.write("tempfile.tmp|50KB|2023-02-10|2023-02-11|Low|Temporary file\n")

print("✅ Test data generated successfully in ./test directory")
