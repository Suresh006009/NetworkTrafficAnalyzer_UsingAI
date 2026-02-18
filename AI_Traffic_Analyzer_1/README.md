# 🛡️ NetGuard AI - Network Traffic Analyzer v2.0

**NetGuard AI** is a lightweight, real-time network surveillance tool built with Python. It captures local network traffic, visualizes bandwidth usage, and uses statistical analysis to detect potential security threats like **Port Scans** and **DoS Attacks**.

![Project Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 Features (v2.0)

### 📊 Real-Time Dashboard
* **Live Traffic Feed:** See every packet entering/leaving your system (Source, Destination, Protocol, Size).
* **Network Speedometer:** Real-time throughput graph (KB/s) to monitor bandwidth usage.
* **Protocol Breakdown:** Doughnut chart showing TCP vs. UDP vs. Other traffic distribution.
* **Top Talkers:** Live ranking of IPs consuming the most bandwidth.

### 🧠 AI Threat Detection
* **DoS/DDoS Detection:** Flags IPs sending an abnormal volume of requests (>50 packets/2s).
* **Port Scan Detection:** Identifies IPs attempting to access multiple ports in rapid succession.
* **Alert System:** Instant red-alert notifications on the dashboard when threats are detected.

### 🛠️ Technical Highlights
* **Backend:** Python (Flask, Scapy, SQLite).
* **Frontend:** HTML5, Bootstrap 5 (Dark Mode), Chart.js.
* **Communication:** WebSockets (Flask-SocketIO) for zero-latency updates.
* **Bypass:** Runs with Admin privileges to access raw network interfaces directly.

---

## ⚙️ Prerequisites

Before running the tool, ensure you have the following installed on Windows:

1.  **Python 3.10+**: [Download Here](https://www.python.org/downloads/) (Make sure to check "Add to PATH").
2.  **Npcap Driver**: [Download Here](https://npcap.com/).
    * *CRITICAL:* During installation, check the box **"Install Npcap in WinPcap API-compatible Mode"**.

---

## 📥 Installation

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *(If `requirements.txt` is missing, run: `pip install flask flask-socketio scapy eventlet`)*

---

## ▶️ Usage

### Option 1: The One-Click Script (Recommended)
Double-click the `run_analyzer.bat` file.
* This automatically requests Administrator privileges (required for packet sniffing).
* It sets up the environment and launches the server.

### Option 2: Manual Start
Open Command Prompt **as Administrator** and run:
```bash

python app.py
