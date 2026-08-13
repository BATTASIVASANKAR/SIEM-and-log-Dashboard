import sqlite3
import os
import random
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

DEVICES = [
    {"name": "fw-01.corp.local", "type": "Firewall", "ip_address": "192.168.1.1", "status": "Online"},
    {"name": "ad-dc-01.corp.local", "type": "Server", "ip_address": "192.168.1.10", "status": "Online"},
    {"name": "web-prod-01.corp.local", "type": "Server", "ip_address": "192.168.1.50", "status": "Online"},
    {"name": "endpoint-ceo.corp.local", "type": "Endpoint", "ip_address": "192.168.1.100", "status": "Online"},
    {"name": "border-router.corp.local", "type": "Router", "ip_address": "10.0.0.1", "status": "Online"},
    {"name": "app-portal.corp.local", "type": "Application", "ip_address": "192.168.1.60", "status": "Online"}
]

USERNAMES = ["admin", "administrator", "root", "ceo_user", "jsmith", "dnoe", "svc-backup", "db_user", "guest"]
EXTERNAL_IPS = ["198.51.100.42", "203.0.113.88", "45.227.254.12", "185.220.101.5", "103.88.22.15", "85.25.103.44", "194.26.135.8"]
CATEGORIES = ["Authentication", "Network", "Malware", "System", "Access"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

LOG_TEMPLATES = {
    "Authentication": [
        {"desc": "Successful user login for '{username}' via SSH", "severity": "Info", "status": "Closed"},
        {"desc": "Successful user login for '{username}' via RDP", "severity": "Low", "status": "Closed"},
        {"desc": "Failed login attempt for user '{username}' - Invalid credentials", "severity": "Medium", "status": "Active"},
        {"desc": "Multiple failed login attempts for user '{username}' (Potential Brute Force)", "severity": "Critical", "status": "Active"},
        {"desc": "User account '{username}' temporarily locked out due to login failures", "severity": "High", "status": "Active"},
        {"desc": "Password reset requested for user '{username}'", "severity": "Info", "status": "Closed"}
    ],
    "Network": [
        {"desc": "Inbound connection allowed from {src_ip}:{port_src} to {dst_ip}:{port_dst}", "severity": "Info", "status": "Closed"},
        {"desc": "Outbound connection initiated to {src_ip}:{port_dst}", "severity": "Info", "status": "Closed"},
        {"desc": "Inbound packet blocked from {src_ip} targeting port {port_dst} (Rule: Block_All_External)", "severity": "Low", "status": "Closed"},
        {"desc": "Port scanning activity detected from IP {src_ip} (Rule: Port_Scan_Detected)", "severity": "High", "status": "Active"},
        {"desc": "High DNS query volume to unrecognized domain '{domain}'", "severity": "Medium", "status": "Active"},
        {"desc": "IDS alert: Potential SQL injection signature matched in URI parameters", "severity": "High", "status": "Active"}
    ],
    "Malware": [
        {"desc": "Antivirus alert: Suspicious process '{process}' quarantined on endpoint", "severity": "High", "status": "Active"},
        {"desc": "Antivirus alert: Trojan.Generic download blocked in browser", "severity": "High", "status": "Active"},
        {"desc": "Heuristic engine: Ransomware-like file modifications detected on system", "severity": "Critical", "status": "Active"},
        {"desc": "Suspicious PowerShell execution bypassing execution policy detected", "severity": "High", "status": "Active"}
    ],
    "System": [
        {"desc": "Disk usage exceeded 90% threshold on drive C:", "severity": "Medium", "status": "Active"},
        {"desc": "CPU utilization spike: 98% sustained over 10 minutes", "severity": "Low", "status": "Closed"},
        {"desc": "System service '{service}' restarted unexpectedly", "severity": "Medium", "status": "Active"},
        {"desc": "Critical system patch applied successfully", "severity": "Info", "status": "Closed"},
        {"desc": "NTP time synchronization failed with peer", "severity": "Low", "status": "Closed"}
    ],
    "Access": [
        {"desc": "Sensitive database configuration file read by user '{username}'", "severity": "Medium", "status": "Active"},
        {"desc": "Database schema modification executed by user '{username}'", "severity": "High", "status": "Active"},
        {"desc": "Privilege escalation: User '{username}' added to group 'Administrators'", "severity": "Critical", "status": "Active"},
        {"desc": "Access denied: Unauthorized attempt to write to system directory by '{username}'", "severity": "Medium", "status": "Active"}
    ]
}

PROCESSES = ["chrome.exe", "svchost.exe", "powershell.exe", "miner.exe", "mimikatz.exe", "explorer.exe", "unknown.exe"]
DOMAINS = ["malicious-cnc-server.ru", "crypto-mining-pool.org", "phishing-login-page.net", "github.com", "google.com"]
SERVICES = ["mssqlserver", "docker", "nginx", "active_directory_ds", "winlogon"]

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            hostname TEXT NOT NULL,
            device_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            username TEXT,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL
        )
    ''')

    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            timestamp TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            assigned_to TEXT,
            FOREIGN KEY(log_id) REFERENCES logs(id)
        )
    ''')

    # Create devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            last_log_received TEXT,
            cpu_usage INTEGER DEFAULT 0,
            ram_usage INTEGER DEFAULT 0
        )
    ''')

    # Check if database is empty, if so, seed it
    cursor.execute("SELECT COUNT(*) FROM devices")
    if cursor.fetchone()[0] == 0:
        seed_devices(conn)

    cursor.execute("SELECT COUNT(*) FROM logs")
    if cursor.fetchone()[0] == 0:
        seed_historical_logs(conn)

    conn.commit()
    conn.close()

def seed_devices(conn):
    cursor = conn.cursor()
    for dev in DEVICES:
        cursor.execute('''
            INSERT INTO devices (name, type, ip_address, status, last_log_received, cpu_usage, ram_usage)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            dev["name"],
            dev["type"],
            dev["ip_address"],
            dev["status"],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            random.randint(10, 60),
            random.randint(20, 70)
        ))
    conn.commit()

def generate_single_log(timestamp_dt, force_critical=False):
    category = random.choice(CATEGORIES)
    device = random.choice(DEVICES)
    hostname = device["name"]
    device_type = device["type"]
    
    # Pick template
    template_list = LOG_TEMPLATES[category]
    if force_critical:
        # filter for critical or high
        crit_templates = [t for t in template_list if t["severity"] in ["Critical", "High"]]
        template = random.choice(crit_templates) if crit_templates else template_list[0]
    else:
        template = random.choice(template_list)
        
    severity = template["severity"]
    status = template["status"]
    
    # Format description with placeholders
    username = random.choice(USERNAMES)
    src_ip = random.choice(EXTERNAL_IPS) if severity in ["Critical", "High", "Medium"] else f"192.168.1.{random.randint(100, 254)}"
    dst_ip = device["ip_address"]
    
    # Keep some IPs internal
    if random.random() > 0.6 and severity not in ["Critical", "High"]:
        src_ip = f"192.168.1.{random.randint(2, 99)}"
        
    desc_raw = template["desc"]
    description = desc_raw.format(
        username=username,
        src_ip=src_ip,
        dst_ip=dst_ip,
        port_src=random.randint(1024, 65535),
        port_dst=random.choice([80, 443, 22, 3389, 445, 1433, 8080]),
        domain=random.choice(DOMAINS),
        process=random.choice(PROCESSES),
        service=random.choice(SERVICES)
    )
    
    return {
        "timestamp": timestamp_dt.strftime('%Y-%m-%d %H:%M:%S'),
        "hostname": hostname,
        "device_type": device_type,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "username": username if ("username" in desc_raw or category in ["Authentication", "Access"]) else None,
        "severity": severity,
        "category": category,
        "description": description,
        "status": status
    }

def seed_historical_logs(conn):
    cursor = conn.cursor()
    
    # Seed logs for the last 7 days
    now = datetime.now()
    total_logs = 1200
    
    # Generate timestamp sequences spread over 7 days
    # More logs near the current time
    timestamps = []
    for i in range(total_logs):
        # Quadratic or exponential distribution to have more recent logs
        ratio = (i / total_logs) ** 1.5
        delta_seconds = int(7 * 24 * 3600 * (1 - ratio))
        log_time = now - timedelta(seconds=delta_seconds)
        # Add slight randomness
        log_time += timedelta(seconds=random.randint(-60, 60))
        timestamps.append(log_time)
        
    timestamps.sort()
    
    # Create predefined incidents at specific historic moments to make the data interesting
    incidents = [
        # Ransomware event
        {"time": now - timedelta(days=2, hours=4), "host": "endpoint-ceo.corp.local", "category": "Malware", "severity": "Critical", "desc": "Heuristic engine: Ransomware-like file modifications detected on system", "title": "Ransomware Activity Detected"},
        # Brute Force attack
        {"time": now - timedelta(days=5, hours=10), "host": "ad-dc-01.corp.local", "category": "Authentication", "severity": "Critical", "desc": "Multiple failed login attempts for user 'administrator' (Potential Brute Force)", "title": "AD Brute Force Attack"},
        # SQL Injection
        {"time": now - timedelta(hours=14), "host": "web-prod-01.corp.local", "category": "Network", "severity": "High", "desc": "IDS alert: Potential SQL injection signature matched in URI parameters", "title": "SQL Injection Attempt"},
    ]
    
    # Helper index for incidents
    incident_times = [inc["time"] for inc in incidents]
    
    for idx, ts in enumerate(timestamps):
        # Check if we should insert an incident instead of random
        is_incident = False
        incident_data = None
        for inc in incidents:
            if abs((ts - inc["time"]).total_seconds()) < 300: # within 5 min
                is_incident = True
                incident_data = inc
                incidents.remove(inc) # insert once
                break
                
        if is_incident:
            dev = next((d for d in DEVICES if d["name"] == incident_data["host"]), DEVICES[0])
            log_data = {
                "timestamp": ts.strftime('%Y-%m-%d %H:%M:%S'),
                "hostname": dev["name"],
                "device_type": dev["type"],
                "source_ip": "185.220.101.5", # Tor IP
                "destination_ip": dev["ip_address"],
                "username": "administrator" if incident_data["category"] == "Authentication" else None,
                "severity": incident_data["severity"],
                "category": incident_data["category"],
                "description": incident_data["desc"],
                "status": "Active"
            }
        else:
            log_data = generate_single_log(ts)
            
        # Insert log
        cursor.execute('''
            INSERT INTO logs (timestamp, hostname, device_type, source_ip, destination_ip, username, severity, category, description, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data["timestamp"],
            log_data["hostname"],
            log_data["device_type"],
            log_data["source_ip"],
            log_data["destination_ip"],
            log_data["username"],
            log_data["severity"],
            log_data["category"],
            log_data["description"],
            log_data["status"]
        ))
        
        log_id = cursor.lastrowid
        
        # If Critical or High severity, create an alert
        if log_data["severity"] in ["Critical", "High"]:
            alert_title = "Critical Security Alert" if log_data["severity"] == "Critical" else "High Severity Threat"
            if is_incident:
                alert_title = incident_data["title"]
            elif "Brute Force" in log_data["description"]:
                alert_title = "Brute Force Attack Detected"
            elif "Ransomware" in log_data["description"]:
                alert_title = "Ransomware Threat Blocked"
            elif "Port scanning" in log_data["description"]:
                alert_title = "Reconnaissance Port Scan"
            elif "SQL injection" in log_data["description"]:
                alert_title = "Web Exploitation Attempt"
            elif "quarantined" in log_data["description"] or "Antivirus" in log_data["description"]:
                alert_title = "Malware Infection Prevented"
                
            cursor.execute('''
                INSERT INTO alerts (log_id, timestamp, title, description, severity, status, assigned_to)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id,
                log_data["timestamp"],
                alert_title,
                log_data["description"],
                log_data["severity"],
                "New",
                random.choice(["Unassigned", "Analyst Alpha", "Analyst Beta"]) if random.random() > 0.4 else "Unassigned"
            ))
            
    conn.commit()

def tick_simulation():
    """
    Checks the last log time, compares with current system time, 
    and inserts dynamic logs to bridge the time gap. 
    Limits logs to a reasonable count if the time difference is large.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get timestamp of the last log
    cursor.execute("SELECT timestamp FROM logs ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return
        
    last_log_time = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    
    time_diff = (now - last_log_time).total_seconds()
    if time_diff <= 0:
        conn.close()
        return
        
    # We want ~1 log every 10 seconds.
    # Calculate how many logs we should generate
    log_interval = 10.0 # seconds
    logs_to_generate = int(time_diff / log_interval)
    
    # Cap generating logs if server was offline for hours
    if logs_to_generate > 50:
        logs_to_generate = 50
        last_log_time = now - timedelta(seconds=500)
        
    for i in range(logs_to_generate):
        log_time = last_log_time + timedelta(seconds=(i + 1) * log_interval)
        
        # 3% chance of a high/critical security event
        force_crit = random.random() < 0.04
        log_data = generate_single_log(log_time, force_critical=force_crit)
        
        # Write to log
        cursor.execute('''
            INSERT INTO logs (timestamp, hostname, device_type, source_ip, destination_ip, username, severity, category, description, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data["timestamp"],
            log_data["hostname"],
            log_data["device_type"],
            log_data["source_ip"],
            log_data["destination_ip"],
            log_data["username"],
            log_data["severity"],
            log_data["category"],
            log_data["description"],
            log_data["status"]
        ))
        
        log_id = cursor.lastrowid
        
        # Update corresponding device's last log received & stats
        cursor.execute('''
            UPDATE devices 
            SET last_log_received = ?, cpu_usage = ?, ram_usage = ?, status = 'Online'
            WHERE name = ?
        ''', (
            log_data["timestamp"],
            random.randint(10, 95),
            random.randint(20, 85),
            log_data["hostname"]
        ))
        
        # If Critical or High, create alert
        if log_data["severity"] in ["Critical", "High"]:
            alert_title = "Critical Security Alert" if log_data["severity"] == "Critical" else "High Severity Threat"
            if "Brute Force" in log_data["description"]:
                alert_title = "Brute Force Attack Detected"
            elif "Ransomware" in log_data["description"]:
                alert_title = "Ransomware Threat Blocked"
            elif "Port scanning" in log_data["description"]:
                alert_title = "Reconnaissance Port Scan"
            elif "SQL injection" in log_data["description"]:
                alert_title = "Web Exploitation Attempt"
            elif "quarantined" in log_data["description"] or "Antivirus" in log_data["description"]:
                alert_title = "Malware Infection Prevented"
                
            cursor.execute('''
                INSERT INTO alerts (log_id, timestamp, title, description, severity, status, assigned_to)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id,
                log_data["timestamp"],
                alert_title,
                log_data["description"],
                log_data["severity"],
                "New",
                "Unassigned"
            ))
            
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized and historical logs seeded successfully.")
