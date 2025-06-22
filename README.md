# IntruNetX-Realtime-Network-Intrusion-Detection-System

> "**Monitoring the unseen, securing the unknown.**"

IntruNet IDS is a lightweight **real-time Intrusion Detection System (IDS)** built using **Flask**, **Scapy**, and **Machine Learning**.  
It captures live network packets, analyzes traffic flows, predicts potential intrusions, and allows the user to **block/unblock suspicious IP addresses** — all through a clean web dashboard.

---
## Screenshots

### 🔐 Password Complexity Checker UI:
![Real Time Detection](ui.png)

### 🧠 Keylogger Log Output:
![Block Attack IP Addresses](output.png)

## Features 🚀

- **Real-time network traffic capture**  
- **Flow-based packet feature extraction**
- **Machine Learning prediction** (attack detection)
- **Block and Unblock IPs** dynamically
- **CSV Export** for captured traffic
- **Responsive web dashboard** with Bootstrap
- **Lightweight and easy to run locally**

---

## Technologies Used 🛠️

- **Python 3.10+**
- **Flask** (Backend Web Server)
- **Scapy** (Packet Sniffing)
- **scikit-learn** (ML Model for prediction)
- **Bootstrap 5** (Frontend styling)
- **HTML + JS** (Frontend dashboard)

---

## Installation 📦

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Rushi19-04/IntruNetX-Realtime-Network-Intrusion-Detection-System.git
   cd IntruNet-IDS
   ```

2. **Install the required libraries**
   ```bash
   pip install -r requirements.txt
   ```

3. **Check/Install WinPcap/Npcap** (For packet sniffing on Windows)

4. **Place the Trained ML Model**
   - Ensure `model.pkl` and `scaler.pkl` are inside the `model/` directory.

---

## How to Run 🚀

1. Start the Flask server:
   ```bash
   python app.py
   ```

2. Open your browser and visit:
   ```
   http://127.0.0.1:5000
   ```

3. Use the Web UI to:
   - **Start Capture**  
   - **Stop Capture**  
   - **Monitor Live Traffic**  
   - **Block/Unblock IPs**  
   - **Export Captured Data to CSV**

---

## Project Structure 📂

```plaintext
IntruNet-IDS/
│
├── app.py                 # Main Flask Application
├── predict.py             # Machine Learning Predictor
├── model/
│   ├── model.pkl          # Pre-trained ML Model
│   └── scaler.pkl         # Feature Scaler
├── templates/
│   └── home.html          # Frontend Web Dashboard
├── static/                # (optional for css/js if extended)
├── captured_traffic.csv   # Exported CSV (after clicking export)
├── requirements.txt       # Python dependencies
└── README.md              # Project Documentation
```

---

## Requirements 🧪

- Python 3.10 or higher
- Flask
- Scapy
- scikit-learn
- pandas
- joblib
- numpy

(Already listed inside `requirements.txt`)

---

## Future Improvements 🌟

- Add automatic alerting/email notification on attacks
- Add graphs and visualizations (e.g., live traffic graphs)
- Support for offline PCAP file analysis
- Extended prediction with multiple attack categories
- Integrate deeper packet inspection

---

## Disclaimer ⚡

> **IntruNet IDS** is meant for educational, research, and local network monitoring purposes only. Unauthorized scanning or interception of third-party networks without consent is illegal.

---

## Credits 🙌

Made with ❤️ by Rushikesh | Viraj | Devendra | Shubham

