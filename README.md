# Enterprise SIEM & Log Monitoring Dashboard

A lightweight, responsive Security Information and Event Management (SIEM) system designed to aggregate, correlate, and analyze security telemetry across enterprise infrastructure including firewalls, servers, endpoints, and application runtimes.

This application features a modern dark-theme cybersecurity dashboard with real-time log ingestion simulation, threat scoring, interactive analytics charts, and incident triage workflows.

---

## 🚀 Key Features

*   **Real-time Log Collection & Simulation:** Automatically generates realistic network, authentication, malware, system, and access logs to simulate enterprise infrastructure telemetry.
*   **Security Alerts & Threat Scoring:** Analyzes incoming logs and flags critical/high-severity threats (e.g., Ransomware, Brute-Force, SQL Injection) with a dynamic global Threat Score calculated on active security events.
*   **Log Management Interface:** Interactive, paginated logs table with advanced multi-parameter filters (by severity, device hostname, log category, date range, or full-text query search).
*   **Incident Response Console:** Enables security analysts to change status, assign owners, investigate, mitigate, or mark incidents as false positives.
*   **Interactive Analytics & Charts:** Visualizes trends using Chart.js—including log severity breakdown, 7-day alert timeline, device log counts, and alert distribution.
*   **System Health Dashboard:** Live-monitors active devices (Firewalls, Domain Controllers, Endpoints, border routers) and aggregates metrics like CPU and RAM usage.

---

## 🛠️ Technology Stack

*   **Backend:** Python 3, Flask (Web Server), SQLite (Relational Database)
*   **Frontend:** HTML5, CSS3, Bootstrap 5 (Styling & Layout), Bootstrap Icons
*   **Visualization:** Chart.js (Interactive charts and graphs)
*   **Database Interface:** `sqlite3` with auto-seeding for historical logs and devices.

---

## 📁 Project Structure

```text
├── app.py              # Main Flask application and API endpoints
├── db_manager.py       # SQLite database initialization, seeding, and simulation logic
├── database.db         # Auto-generated SQLite database file
├── requirements.txt    # Python dependencies
├── static/
│   ├── css/
│   │   └── styles.css  # Custom cyber-themed styles and glassmorphism styling
│   └── js/
│       └── main.js     # Shared front-end logic and event hooks
└── templates/
    ├── base.html       # Base layout with sidebar, navigation bar, global clock, and live Threat Score
    ├── index.html      # Landing page / Welcome page
    ├── dashboard.html  # Live system status dashboard
    ├── logs.html       # Syslog explorer and inspection console
    ├── alerts.html     # Security alert management console
    ├── analytics.html  # Incident and log analytics charting dashboard
    └── incidents.html  # High-priority security incident monitoring and response room
```

---

## ⚙️ Installation & Setup

### Prerequisites
*   Python 3.8 or higher installed on your system.

### Steps to Run
1.  **Clone or Open Project Directory**
    Ensure you are in the directory containing the project code:
    ```bash
    cd "SIEM and log dashboard/project"
    ```

2.  **Create a Virtual Environment (Recommended)**
    ```bash
    python -m venv venv
    ```

3.  **Activate the Virtual Environment**
    *   **Windows (PowerShell):**
        ```powershell
        .\venv\Scripts\Activate.ps1
        ```
    *   **Windows (CMD):**
        ```cmd
        .\venv\Scripts\activate.bat
        ```
    *   **Linux / macOS:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Initialize Database & Run Application**
    When run for the first time, the database will automatically initialize and populate with 7 days of historical logs.
    ```bash
    python app.py
    ```

6.  **Access the Dashboard**
    Open your browser and navigate to:
    👉 [**http://127.0.0.1:5000**](http://127.0.0.1:5000)

---

## 💡 How the Simulation Works
The background threat simulator updates database records incrementally on page navigation or API polling:
*   On every `/api/stats` call (polled every 10 seconds), the system runs `tick_simulation()`.
*   It calculates the time difference since the last log entry and injects new events proportionally.
*   Random chance seeds (approx. 4%) trigger security threats like *Malware Infection*, *Brute Force*, or *SQL Injection* to test responder workflows in real time.
