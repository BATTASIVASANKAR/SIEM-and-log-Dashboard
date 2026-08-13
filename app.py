import os
from flask import Flask, render_template, jsonify, request, send_file
from datetime import datetime, timedelta
from db_manager import init_db, tick_simulation, get_db_connection

app = Flask(__name__)

# Ensure DB is initialized on startup
init_db()

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def format_stats():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Total logs
    cur.execute('SELECT COUNT(*) FROM logs')
    total_logs = cur.fetchone()[0]
    
    # Critical Alerts
    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'")
    critical_alerts = cur.fetchone()[0]
    
    # Warning Alerts (High and Medium alerts count)
    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('High', 'Medium')")
    warning_alerts = cur.fetchone()[0]
    
    # Information Logs (Low and Info logs count)
    cur.execute("SELECT COUNT(*) FROM logs WHERE severity IN ('Info', 'Low')")
    info_logs = cur.fetchone()[0]
    
    # Active Devices
    cur.execute("SELECT COUNT(*) FROM devices WHERE status='Online'")
    active_devices = cur.fetchone()[0]
    
    # Alerts breakdown for charts
    cur.execute('SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity')
    alerts_distribution = {row['severity']: row['cnt'] for row in cur.fetchall()}
    
    # Threat score (weighted sum of active alerts, capped at 100)
    cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts WHERE status != 'Resolved' GROUP BY severity")
    active_alerts = {row['severity']: row['cnt'] for row in cur.fetchall()}
    severity_weights = {'Critical': 25, 'High': 15, 'Medium': 5, 'Low': 1, 'Info': 0}
    threat_score = 0
    for sev, cnt in active_alerts.items():
        threat_score += severity_weights.get(sev, 0) * cnt
    threat_score = min(threat_score, 100)
    
    # System health (average CPU/RAM of online devices)
    cur.execute("SELECT AVG(cpu_usage) as cpu, AVG(ram_usage) as ram FROM devices WHERE status='Online'")
    health = cur.fetchone()
    
    conn.close()
    
    return {
        'total_logs': total_logs,
        'critical_alerts': critical_alerts,
        'warning_alerts': warning_alerts,
        'info_logs': info_logs,
        'active_devices': active_devices,
        'alerts': alerts_distribution,
        'threat_score': threat_score,
        'cpu_avg': round(health['cpu'] or 0, 1),
        'ram_avg': round(health['ram'] or 0, 1)
    }

# ---------------------------------------------------------------------------
# Page routes (HTML)
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/logs')
def logs_page():
    return render_template('logs.html')

@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@app.route('/analytics')
def analytics_page():
    return render_template('analytics.html')

@app.route('/incidents')
def incidents_page():
    return render_template('incidents.html')

# ---------------------------------------------------------------------------
# API endpoints (JSON) – used by JavaScript for dynamic data
# ---------------------------------------------------------------------------
@app.route('/api/stats')
def api_stats():
    # Simulate background log generation before returning stats
    tick_simulation()
    return jsonify(format_stats())

@app.route('/api/logs/live')
def api_live_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20")
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/logs/filter', methods=['GET'])
def api_logs_filter():
    # Extract query parameters
    severity = request.args.get('severity')
    category = request.args.get('category')
    hostname = request.args.get('hostname')
    start_date = request.args.get('start')  # format: YYYY-MM-DD
    end_date = request.args.get('end')
    search = request.args.get('search')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    offset = (page - 1) * per_page
    
    filters = []
    params = []
    if severity:
        filters.append('severity = ?')
        params.append(severity)
    if category:
        filters.append('category = ?')
        params.append(category)
    if hostname:
        filters.append('hostname = ?')
        params.append(hostname)
    if start_date:
        filters.append('date(timestamp) >= ?')
        params.append(start_date)
    if end_date:
        filters.append('date(timestamp) <= ?')
        params.append(end_date)
    if search:
        filters.append('(description LIKE ? OR hostname LIKE ? OR source_ip LIKE ?)')
        params.append(f'%{search}%')
        params.append(f'%{search}%')
        params.append(f'%{search}%')
        
    where_clause = 'WHERE ' + ' AND '.join(filters) if filters else ''
    
    conn = get_db_connection()
    cur = conn.cursor()
    # Total count for pagination
    count_query = f"SELECT COUNT(*) FROM logs {where_clause}"
    cur.execute(count_query, params)
    total = cur.fetchone()[0]
    # Fetch page data
    data_query = f"SELECT * FROM logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    cur.execute(data_query, params + [per_page, offset])
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify({
        'total': total,
        'page': page,
        'per_page': per_page,
        'logs': rows
    })

@app.route('/api/alerts')
def api_alerts():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, timestamp, title, description, severity, status, assigned_to FROM alerts ORDER BY timestamp DESC')
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/alerts/update', methods=['POST'])
def api_alert_update():
    data = request.get_json()
    alert_id = data.get('id')
    new_status = data.get('status')
    assigned = data.get('assigned_to')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET status = ?, assigned_to = ? WHERE id = ?', (new_status, assigned, alert_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/incidents')
def api_incidents():
    conn = get_db_connection()
    cur = conn.cursor()
    # Incidents correspond to high priority alerts joined with logs to get device info and source/destination IP
    cur.execute('''
        SELECT a.id, a.timestamp, a.title, a.description, a.severity, a.status, a.assigned_to,
               l.hostname, l.source_ip, l.destination_ip, l.device_type
        FROM alerts a
        LEFT JOIN logs l ON a.log_id = l.id
        ORDER BY a.timestamp DESC
    ''')
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/incidents/action', methods=['POST'])
def api_incident_action():
    data = request.get_json()
    incident_id = data.get('id')
    action = data.get('action') # 'investigate', 'mitigate', 'dismiss'
    
    new_status = 'Open'
    if action == 'investigate':
        new_status = 'Under Investigation'
    elif action == 'mitigate':
        new_status = 'Mitigated'
    elif action == 'dismiss':
        new_status = 'False Positive'
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE alerts SET status = ? WHERE id = ?', (new_status, incident_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'new_status': new_status})

@app.route('/api/devices')
def api_devices():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT name, type, ip_address, status, cpu_usage, ram_usage FROM devices')
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/analytics-data')
def api_analytics_data():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Severity Distribution
    cur.execute('SELECT severity, COUNT(*) as cnt FROM logs GROUP BY severity')
    severity_dist = {row['severity']: row['cnt'] for row in cur.fetchall()}
    
    # 2. Timeline (Logs grouped by date and severity in the last 7 days)
    cur.execute('''
        SELECT date(timestamp) as date_val, severity, COUNT(*) as cnt 
        FROM logs 
        WHERE timestamp >= date('now', '-7 days')
        GROUP BY date_val, severity
        ORDER BY date_val ASC
    ''')
    timeline_rows = [dict(row) for row in cur.fetchall()]
    
    # 3. Device activity (logs count per device)
    cur.execute('SELECT hostname, COUNT(*) as cnt FROM logs GROUP BY hostname ORDER BY cnt DESC')
    device_activity = {row['hostname']: row['cnt'] for row in cur.fetchall()}
    
    # 4. Alert Statistics (alerts by severity and by status)
    cur.execute('SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity')
    alert_severity = {row['severity']: row['cnt'] for row in cur.fetchall()}
    
    cur.execute('SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status')
    alert_status = {row['status']: row['cnt'] for row in cur.fetchall()}
    
    conn.close()
    
    return jsonify({
        'severity_distribution': severity_dist,
        'timeline': timeline_rows,
        'device_activity': device_activity,
        'alert_statistics': {
            'severity': alert_severity,
            'status': alert_status
        }
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)



