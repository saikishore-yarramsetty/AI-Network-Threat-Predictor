# AI Network Threat Predictor

A real-time network threat detection system that monitors live network traffic and predicts potential malicious activity using Machine Learning. This project combines **Python, Scapy, and RandomForestClassifier** to analyze packets, map processes, and display insights via terminal or a web dashboard.

---

## About the Project

Network security is crucial for both personal and enterprise environments. This project demonstrates how AI can enhance traditional network monitoring by predicting threats in real-time.

**Key Goals:**
- Capture network packets live from your machine or network.
- Extract key features from each packet (IP, port, packet length, TCP flags, HTTP/HTTPS info, domain, process owner).
- Use a pre-trained **RandomForestClassifier** to classify packets as normal or potentially malicious.
- Log traffic for audit and visualization.
- Provide both CLI and web-based visualization for monitoring.

**Why it’s useful:**
- Bridges the gap between standard packet sniffing and AI-based threat analysis.
- Provides insights on which processes or devices are generating suspicious traffic.
- Can be extended to enterprise monitoring dashboards.

---

## Features

- Real-time packet capture using **Scapy**
- Automatic network interface detection
- Packet logging with timestamp, source/destination IP & ports, process name, owner, prediction, domain, URL path
- AI-based threat prediction using **RandomForestClassifier**
- Optional **TLS certificate lookup** for HTTPS domains
- Optional **SNI extraction** from TLS ClientHello
- Web dashboard visualization (HTML + Chart.js)
- DNS caching & reverse DNS lookup
- CLI output for quick monitoring

---

## Tech Stack

- **Python 3.x**
- **Scapy** – packet capture
- **Pandas** – data handling
- **psutil** – process and connection info
- **joblib** – load/save ML model
- **SSL & socket** – domain lookups
- **Flask + HTML + Chart.js** – optional web dashboard
- **RandomForestClassifier** – Machine Learning for prediction

---

## Project Structure
must be maintained as it is shoen in the repo...

---

## Installation & Setup

Follow these steps to get the project running locally:

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/AI-Network-Threat-Predictor.git
cd AI-Network-Threat-Predictor


2. Install Python
python --version


3. Create a virtual environment (recommended)
python -m venv venv

Windows
venv\Scripts\activate


Linux / MacOS
source venv/bin/activate


4. Install dependencies
pip install -r requirements.txt


5. Train the Machine Learning Model
python train_model.py


Usage
1. CLI Packet Monitoring
python sniff_packets.py


2. GUI Web Dashboard
For a real-time web dashboard:
python app.py


