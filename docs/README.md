# NetWatch  

*A Real-Time Network Monitoring Tool Built with Python, Scapy, and PyQt5*  

NetWatch is an open-source desktop application that captures and analyzes network traffic in real-time. It provides insights into **device activity, visited domains, applications in use, and approximate geolocation**—all within an intuitive **PyQt5 GUI**.  

This project showcases expertise in **Python programming, GUI development, network packet analysis, database management, and security**, making it a strong portfolio piece for software development, cybersecurity, or network engineering roles.  

## 🚀 Features  

- **Real-Time Monitoring** – Captures network traffic with updates every 500ms.  
- **Device Tracking** – Logs IP & MAC addresses, resolving device names where possible.  
- **Domain & App Detection** – Identifies visited websites (DNS) and apps (via port analysis).  
- **Geolocation** – Estimates device locations using IP geolocation services.  
- **Interactive GUI** – Start/Stop monitoring, filter data, and manage logs with a sleek interface.  
- **Secure Operations** – Requires root privileges for sensitive actions.  
- **Persistent Logging** – Stores network activity in an SQLite database.  
- **Debugging Support** – Generates detailed logs for troubleshooting.  

## 🛠 Tech Stack  

- **Python 3.11** – Core language  
- **Scapy** – Packet capture & analysis  
- **PyQt5** – Desktop GUI framework  
- **SQLite** – Data persistence  
- **Requests** – IP geolocation lookups  
- **Netifaces** – Network interface detection  
- **Threading** – For concurrent packet sniffing & UI updates  

## 📥 Installation  

### Prerequisites  
- **Python 3.11+**  
- **Root/admin privileges** (for packet capture)  
- **A network interface** (e.g., Wi-Fi adapter)  

### Steps  

# Clone the repository
```
git clone https://github.com/WabukoWabuko/netwatch.git
cd netwatch
```

# (Optional) Create & activate a virtual environment
```
python -m venv netwatch_env
source netwatch_env/bin/activate  # Linux/Mac
netwatch_env\Scripts\activate     # Windows
```

# Install dependencies
`pip install -r requirements.txt`

# Run the application
`python app/main.py`

# 🎯 Usage  

### Launch NetWatch  
The GUI will start after root authentication.  

### Start Monitoring  
Click **"Start Monitoring"** to begin capturing traffic.  

### View Activity  
The real-time table logs:  
- **Timestamp**  
- **Device Name**  
- **IP & MAC Address**  
- **Visited Site (Domain)**  
- **Application** (based on ports)  
- **Approximate Location** (City, Region, Country)  

### Manage Data  
- **Delete Entry** – Right-click a row → "Delete" (Requires root).  
- **Clear All** – Remove all logs (Requires root).  

### Stop Monitoring  
Click **"Stop Monitoring"** to pause capture.  

---

# 📂 Project Structure  

# 🚀 Future Enhancements  

- **Export Logs** – Save activity history to **CSV or JSON**.  
- **Advanced Filtering** – Search by **IP, domain, or application**.  
- **Cross-Platform Support** – Expand functionality for **Windows/macOS**.  
- **Deep Packet Inspection (DPI)** – More precise **application identification**.  

---

# 🎯 NetWatch demonstrates:  

✔ **Networking Expertise** – Deep understanding of **packet analysis & protocols**.  
✔ **GUI Development** – Hands-on experience with **PyQt5** for intuitive interfaces.  
✔ **Database Management** – Efficient use of **SQLite** for data persistence.  
✔ **Security Awareness** – Secure handling of **privileged operations**.  
✔ **Problem-Solving Skills** – Debugging, optimizing, and iterating on real-world constraints.  
✔ **Scalability & Performance Optimization** – Ensuring **real-time data handling** without performance bottlenecks.  

This project reflects my ability to **design, develop, and refine** a **functional, user-friendly, and security-conscious tool**—relevant for roles in **software development, network engineering, or cybersecurity**.  

---

# 🤝 Contributing  

Contributions are welcome!  

1. **Fork the repo**  
2. Create a new branch:  
   bash
    `git checkout -b feature/your-feature`
# 📜 License  

This project is licensed under the **MIT License**.  

---

# 📬 Contact  

👤 **Wabuko Wabuko**  
🔗 **GitHub:** https://github.com/WabukoWabuko
📧 **Email:** mailto:basilwabbs@gmail.com
💼 **LinkedIn:** https://linkedin.com/in/WabukoWabuko  

