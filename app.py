import os
import joblib
import pandas as pd
import threading
import time
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flow_extract import extract_flows
from bson.objectid import ObjectId
from scapy.all import sniff, IP, TCP, UDP

#CONFIGURATION 
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'niraj-secret-key-2025'

app.config["MONGO_URI"] = "mongodb+srv://nirajsalunkhe08:iamthedanger001@smart.fu1zgdm.mongodb.net/nids_db?retryWrites=true&w=majority"
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#INIT EXTENSIONS
mongo = PyMongo(app)
socketio = SocketIO(app, async_mode='threading')
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#GLOBAL VARS FOR LIVE SNIFFER
SNIFFING_THREAD = None
IS_SNIFFING = False

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.password = user_doc['password']

@login_manager.user_loader
def load_user(user_id):
    try:
        user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user_doc: return User(user_doc)
    except: return None
    return None

#SHARED STYLES
CSS_STYLE = """
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.25/jspdf.plugin.autotable.min.js"></script>

<style>
    body { font-family: 'Inter', sans-serif; background-color: #f4f6f8; color: #2d3748; }
    .navbar { background: #1a202c; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .brand-text { font-weight: 700; letter-spacing: 0.5px; color: #fff; text-decoration: none; }
    
    .stat-card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-left: 5px solid #cbd5e0; }
    .stat-card.danger { border-left-color: #e53e3e; }
    .stat-card.success { border-left-color: #38a169; }
    .stat-title { color: #718096; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; }
    .stat-value { font-size: 2rem; font-weight: 700; color: #1a202c; }
    
    .chart-card { background: white; border-radius: 16px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); height: 300px; }
    
    .auth-card { max-width: 400px; margin: 80px auto; background: white; padding: 40px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); }
    .upload-section { background: white; border-radius: 16px; padding: 40px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
    .btn-primary-custom { background-color: #3182ce; border: none; padding: 12px 30px; border-radius: 8px; font-weight: 600; color: white; }
    .btn-primary-custom:hover { background-color: #2b6cb0; color: white; }

    .table-container { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
    .badge-attack { background-color: #fed7d7; color: #c53030; padding: 5px 10px; border-radius: 6px; font-weight: 600; font-size: 0.8rem; }
    .badge-normal { background-color: #c6f6d5; color: #2f855a; padding: 5px 10px; border-radius: 6px; font-weight: 600; font-size: 0.8rem; }
    
    /* Live Monitor Specifics */
    .terminal-bg { background-color: #1e1e1e; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; border-radius: 10px; height: 400px; overflow-y: auto; box-shadow: inset 0 0 10px #000; }
    .live-alert { color: #ff3333; font-weight: bold; text-shadow: 0 0 5px rgba(255, 0, 0, 0.5); }
    
    .btn-stop { background-color: #e53e3e; color: white; font-weight: bold; border: none; }
    .btn-stop:hover { background-color: #c53030; color: white; }
    
    .btn-resume { background-color: #38a169; color: white; font-weight: bold; border: none; }
    .btn-resume:hover { background-color: #2f855a; color: white; }

    .export-controls { display: none; } /* Hidden by default until stopped */
</style>
"""

# --- LIVE MONITOR TEMPLATE
LIVE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Live NIDS Monitor</title>""" + CSS_STYLE + """</head>
<body>
<nav class="navbar navbar-dark mb-4">
  <div class="container">
    <a class="navbar-brand brand-text" href="/">NIDS Sentinel - LIVE</a>
    <div><a href="/" class="btn btn-sm btn-outline-light">Back to Upload</a></div>
  </div>
</nav>

<div class="container">
    <div class="row mb-4 align-items-center">
        <div class="col-md-6">
            <h2 class="fw-bold">Real-Time Traffic Analysis</h2>
            <p class="text-muted mb-0">Monitoring network interface for suspicious packets...</p>
        </div>
        <div class="col-md-6 text-end">
            <button id="btn-toggle" class="btn btn-stop px-4 py-2 me-2" onclick="toggleSniffing()">STOP MONITORING</button>
            
            <div id="export-area" class="export-controls d-inline-block">
                <button class="btn btn-success" onclick="downloadCSV()"> Export CSV</button>
                <button class="btn btn-danger" onclick="downloadPDF()"> Export PDF</button>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-3">
        <div class="col-md-4"><div class="stat-card"><div class="stat-title">Packets Scanned</div><div class="stat-value" id="pkt-count">0</div></div></div>
        <div class="col-md-4"><div class="stat-card danger"><div class="stat-title">Threats Detected</div><div class="stat-value text-danger" id="threat-count">0</div></div></div>
        <div class="col-md-4"><div class="stat-card"><div class="stat-title">Status</div><div class="stat-value fs-4" id="status-text">Active </div></div></div>
    </div>

    <div class="row">
        <div class="col-md-12">
            <div class="terminal-bg" id="log-window">
                <div>[SYSTEM] Initializing Live Sniffer...</div>
                <div>[SYSTEM] Connected to Server...</div>
            </div>
        </div>
    </div>
</div>

<script>
    var socket = io();
    var pktCount = 0;
    var threatCount = 0;
    
    // Store ALL packets here. When we "Resume", we just keep adding to this list.
    var allPackets = []; 
    var isRunning = true;

    socket.on('connect', function() {
        console.log("Connected to WebSocket");
    });

    socket.on('packet_data', function(msg) {
        if (!isRunning) return; // Ignore packets if paused (just in case)

        pktCount++;
        document.getElementById('pkt-count').innerText = pktCount;
        
        // Save to our persistent list
        allPackets.push(msg);

        var logWin = document.getElementById('log-window');
        var newLine = document.createElement('div');
        
        var logText = `[${msg.time}] ${msg.proto} | ${msg.src} -> ${msg.dst}:${msg.port} | Len: ${msg.len}`;
        
        if (msg.risk === 'High') {
            threatCount++;
            document.getElementById('threat-count').innerText = threatCount;
            newLine.innerHTML = `<span class="live-alert"> ALERT: ${logText} (Suspicious Port/Flag)</span>`;
        } else {
            newLine.innerText = logText;
        }

        logWin.insertBefore(newLine, logWin.firstChild);
    });

    // --- TOGGLE FUNCTION (STOP / RESUME) ---
    function toggleSniffing() {
        var btn = document.getElementById('btn-toggle');
        var status = document.getElementById('status-text');
        var exports = document.getElementById('export-area');
        var logWin = document.getElementById('log-window');

        if (isRunning) {
            // ACTION: STOP
            socket.emit('stop_sniffer');
            isRunning = false;
            
            // UI Updates
            btn.innerText = "▶ RESUME MONITORING";
            btn.classList.remove('btn-stop');
            btn.classList.add('btn-resume');
            
            status.innerText = "Paused ";
            exports.style.display = "inline-block"; // Show Export Buttons
            
            var msg = document.createElement('div');
            msg.style.color = "yellow";
            msg.innerText = "[SYSTEM] Paused. You can now export the data.";
            logWin.insertBefore(msg, logWin.firstChild);
            
        } else {
            // ACTION: RESUME
            socket.emit('start_sniffer');
            isRunning = true;
            
            // UI Updates
            btn.innerText = " STOP MONITORING";
            btn.classList.remove('btn-resume');
            btn.classList.add('btn-stop');
            
            status.innerText = "Active ";
            exports.style.display = "none"; // Hide Export Buttons while running
            
            var msg = document.createElement('div');
            msg.style.color = "#00ff00";
            msg.innerText = "[SYSTEM] Resumed Monitoring...";
            logWin.insertBefore(msg, logWin.firstChild);
        }
    }

    // --- EXPORT TO CSV (Includes ALL data from start) ---
    function downloadCSV() {
        if (allPackets.length === 0) { alert("No data to export!"); return; }
        
        let csvContent = "data:text/csv;charset=utf-8,";
        csvContent += "Time,Protocol,Source IP,Destination IP,Port,Length,Risk Level\\n"; 

        allPackets.forEach(function(p) {
            let row = `${p.time},${p.proto},${p.src},${p.dst},${p.port},${p.len},${p.risk}`;
            csvContent += row + "\\n";
        });

        var encodedUri = encodeURI(csvContent);
        var link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", "nids_live_report_full.csv");
        document.body.appendChild(link);
        link.click();
    }

    // --- EXPORT TO PDF (Includes ALL data from start) ---
    function downloadPDF() {
        if (allPackets.length === 0) { alert("No data to export!"); return; }
        
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();

        doc.setFontSize(18);
        doc.text("NIDS Live Capture Report (Full Session)", 14, 22);
        doc.setFontSize(11);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 30);
        doc.text(`Total Packets Captured: ${pktCount} | Threats: ${threatCount}`, 14, 38);

        var tableData = allPackets.map(p => [p.time, p.proto, p.src, p.dst, p.port, p.risk]);

        doc.autoTable({
            startY: 45,
            head: [['Time', 'Proto', 'Source', 'Destination', 'Port', 'Risk']],
            body: tableData,
            theme: 'grid',
            styles: { fontSize: 8 },
            headStyles: { fillColor: [44, 62, 80] },
            didParseCell: function(data) {
                if (data.section === 'body' && data.row.raw[5] === 'High') {
                    data.cell.styles.textColor = [255, 0, 0];
                    data.cell.styles.fontStyle = 'bold';
                }
            }
        });

        doc.save("nids_live_report_full.pdf");
    }
</script>
</body>
</html>
"""

# --- ORIGINAL TEMPLATES

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Login - NIDS</title>""" + CSS_STYLE + """</head>
<body>
<nav class="navbar navbar-dark mb-4"><div class="container"><a class="navbar-brand brand-text" href="/"> NIDS Sentinel</a></div></nav>
<div class="container">
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="alert alert-warning text-center">{% for msg in messages %}{{ msg }}{% endfor %}</div>{% endif %}
    {% endwith %}
    <div class="auth-card text-center">
        <h3 class="mb-4 fw-bold">Login to History</h3>
        <p class="text-muted mb-4">Login to save your scan reports automatically.</p>
        <form method="POST">
            <input type="text" name="username" class="form-control mb-3" placeholder="Username" required>
            <input type="password" name="password" class="form-control mb-4" placeholder="Password" required>
            <button class="btn btn-primary-custom w-100 mb-3" type="submit">Access History</button>
        </form>
        <a href="/register" class="text-decoration-none small">Create an Account</a>
        <br><br>
        <a href="/" class="text-muted small">← Back to Guest Scanner</a>
    </div>
</div>
</body>
</html>
"""

REGISTER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Register - NIDS</title>""" + CSS_STYLE + """</head>
<body>
<nav class="navbar navbar-dark mb-4"><div class="container"><a class="navbar-brand brand-text" href="/"> NIDS Sentinel</a></div></nav>
<div class="container">
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="alert alert-warning text-center">{% for msg in messages %}{{ msg }}{% endfor %}</div>{% endif %}
    {% endwith %}
    <div class="auth-card text-center">
        <h3 class="mb-4 fw-bold">Register</h3>
        <form method="POST">
            <input type="text" name="username" class="form-control mb-3" placeholder="Username" required>
            <input type="password" name="password" class="form-control mb-4" placeholder="Password" required>
            <button class="btn btn-primary-custom w-100 mb-3" type="submit">Sign Up</button>
        </form>
        <a href="/login" class="text-decoration-none small">Already have an account?</a>
    </div>
</div>
</body>
</html>
"""

HISTORY_TEMPLATE = """
<!doctype html>
<html lang="en">
<head><title>Scan History</title>""" + CSS_STYLE + """</head>
<body>
<nav class="navbar navbar-dark mb-4">
  <div class="container">
    <a class="navbar-brand brand-text" href="/"> NIDS Sentinel</a>
    <div>
        <a href="/" class="btn btn-sm btn-outline-light me-2">Back to Dashboard</a>
        <a href="/logout" class="btn btn-sm btn-danger">Logout</a>
    </div>
  </div>
</nav>
<div class="container">
    <div class="table-container">
        <h3 class="mb-4 fw-bold">Scan History <span class="text-muted fs-6">({{ current_user.username }})</span></h3>
        {% if scans %}
        <table class="table table-hover align-middle">
            <thead class="table-light">
                <tr><th>Date</th><th>File Name</th><th>Total Flows</th><th>Attacks</th><th>Threat Level</th></tr>
            </thead>
            <tbody>
            {% for scan in scans %}
                <tr>
                    <td>{{ scan.date.strftime('%Y-%m-%d %H:%M') }}</td>
                    <td class="fw-bold">{{ scan.filename }}</td>
                    <td>{{ scan.total_flows }}</td>
                    <td class="text-danger fw-bold">{{ scan.attacks_found }}</td>
                    <td>
                        {% if scan.threat_level > 20 %}
                            <span class="badge bg-danger">{{ "%.1f"|format(scan.threat_level) }}%</span>
                        {% else %}
                            <span class="badge bg-success">{{ "%.1f"|format(scan.threat_level) }}%</span>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
        {% else %}
            <p class="text-center text-muted py-5">No scan history found for this user.</p>
        {% endif %}
    </div>
</div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NIDS Dashboard</title>
    """ + CSS_STYLE + """
    <style>
        /* Desktop-Specific Tweaks */
        @media (min-width: 768px) {
            .action-bar { justify-content: space-between; align-items: center; }
            .btn-group-custom { display: flex; gap: 10px; }
            .btn-custom-action { width: auto; padding-left: 20px; padding-right: 20px; }
        }
        /* Mobile-Specific Tweaks */
        @media (max-width: 767px) {
            .action-bar { flex-direction: column; align-items: flex-start; gap: 15px; }
            .btn-group-custom { display: flex; flex-direction: column; width: 100%; gap: 10px; }
            .btn-custom-action { width: 100%; padding: 12px; }
            .report-header { margin-bottom: 5px; }
        }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark mb-4">
  <div class="container">
    <a class="navbar-brand brand-text" href="/"> NIDS Sentinel</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <div class="navbar-nav ms-auto mt-2 mt-lg-0">
        <a href="/live" class="btn btn-sm btn-danger mb-2 mb-lg-0 me-lg-2 w-100"> Live Monitor</a>
        {% if current_user.is_authenticated %}
            <span class="text-white me-3 align-self-center d-none d-lg-block">User: {{ current_user.username }}</span>
            <a href="/history" class="btn btn-sm btn-outline-light mb-2 mb-lg-0 me-lg-2 w-100"> History</a>
            <a href="/logout" class="btn btn-sm btn-outline-danger w-100">Logout</a>
        {% else %}
            <a href="/login" class="btn btn-sm btn-outline-info w-100">Login</a>
        {% endif %}
      </div>
    </div>
  </div>
</nav>

<div class="container pb-5">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ 'danger' if category == 'error' else 'info' }}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% if not results %}
  <div class="row justify-content-center mt-4">
    <div class="col-12 col-md-8 col-lg-6">
      <div class="upload-section">
        <div class="mb-3"><span style="font-size: 3rem;">📁</span></div>
        <h3 class="fw-bold mb-2">Upload Traffic Capture</h3>
        <p class="text-muted mb-4">Select a .pcap file to analyze.</p>
        <form id="uploadForm" method="post" action="/" enctype="multipart/form-data">
          <input type="file" name="pcap" class="form-control mb-3" accept=".pcap,.pcapng" required>
          <button class="btn btn-primary-custom" type="submit">Generate Report</button>
        </form>
        {% if not current_user.is_authenticated %}
        <p class="mt-3 small text-muted">Scan as Guest. <a href="/login">Login</a> to save results.</p>
        {% endif %}
      </div>
    </div>
  </div>
  {% endif %}

  {% if results %}
  
  <div class="d-flex action-bar mb-4 p-3 bg-white rounded shadow-sm border">
    <div class="report-header">
        <h2 class="fw-bold mb-0 text-dark">Analysis Report</h2>
        <small class="text-muted">Generated: {{ date_now }}</small>
    </div>
    
    <div class="btn-group-custom">
        <button onclick="downloadReportCSV()" class="btn btn-outline-success btn-custom-action">
             Export CSV
        </button>
        <button onclick="downloadReportPDF()" class="btn btn-outline-danger btn-custom-action">
            Export PDF
        </button>
        <a href="/" class="btn btn-primary btn-custom-action">
             New Scan
        </a>
    </div>
  </div>

  <div class="row g-3 mb-4">
    <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-title">Total Flows</div><div class="stat-value">{{ summary.total }}</div></div></div>
    <div class="col-6 col-md-3"><div class="stat-card danger"><div class="stat-title">Threats</div><div class="stat-value text-danger">{{ summary.attacks }}</div></div></div>
    <div class="col-6 col-md-3"><div class="stat-card success"><div class="stat-title">Safe</div><div class="stat-value text-success">{{ summary.normal }}</div></div></div>
    <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-title">Risk Level</div><div class="stat-value" style="color: {{ 'red' if summary.threat_level > 20 else 'green' }}">{{ "%.0f"|format(summary.threat_level) }}%</div></div></div>
  </div>

  <div class="table-container mb-5">
    <div class="table-responsive">
        <table class="table table-hover align-middle" id="reportTable">
            <thead class="table-light"><tr><th>Source</th><th>Dest</th><th>Proto</th><th>Verdict</th></tr></thead>
            <tbody>
            {% for r in results %}
            <tr class="{{ 'table-danger' if r.pred == 1 else '' }}">
                <td>{{ r.src }}</td><td>{{ r.dst }}</td>
                <td>{{ 'TCP' if r.proto == 6 else 'UDP' }}</td>
                <td>{% if r.pred == 1 %}<span class="badge-attack">MALICIOUS</span>{% else %}<span class="badge-normal">NORMAL</span>{% endif %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
  </div>
  {% endif %}
</div>

<script>
    function downloadReportCSV() {
        var table = document.getElementById("reportTable");
        var rows = table.querySelectorAll("tr");
        var csv = [];
        for (var i = 0; i < rows.length; i++) {
            var row = [], cols = rows[i].querySelectorAll("td, th");
            for (var j = 0; j < cols.length; j++) row.push(cols[j].innerText);
            csv.push(row.join(","));
        }
        var csvFile = new Blob([csv.join("\\n")], {type: "text/csv"});
        var link = document.createElement("a");
        link.href = URL.createObjectURL(csvFile);
        link.download = "nids_offline_report.csv";
        document.body.appendChild(link);
        link.click();
    }

    function downloadReportPDF() {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.text("NIDS Security Scan Report", 14, 20);
        doc.setFontSize(10);
        doc.text("Generated via PCAP Analysis", 14, 28);

        doc.autoTable({ 
            html: '#reportTable',
            startY: 35,
            theme: 'grid',
            styles: { fontSize: 8 },
            headStyles: { fillColor: [44, 62, 80] },
            didParseCell: function(data) {
                if (data.section === 'body' && data.cell.text[0].includes('MALICIOUS')) {
                    data.cell.styles.textColor = [255, 0, 0];
                }
            }
        });
        doc.save("nids_offline_report.pdf");
    }
</script>
</body>
</html>
"""

# --- LOGIC ---
MODEL = None
COLUMNS = None

def load_ml_model():
    global MODEL, COLUMNS
    path = "nids_model.joblib"
    if os.path.exists(path):
        obj = joblib.load(path)
        MODEL = obj['model']
        COLUMNS = obj['columns']
        print("[+] Model Loaded")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def prepare_df(flow_df):
    X = flow_df.select_dtypes(include=['number']).copy()
    if COLUMNS:
        for c in COLUMNS:
            if c not in X.columns: X[c] = 0
        X = X[COLUMNS]
    return X.fillna(0)

#LIVE SNIFFER LOGIC
def background_sniffer():
    global IS_SNIFFING
    print("[*] Sniffer Thread Started...")
    
    # We loop here to check if we should stop
    while True:
        if IS_SNIFFING:
            # capture a few packets, then loop to check IS_SNIFFING again
            sniff(prn=process_packet, count=5, timeout=1, store=0)
        else:
            time.sleep(1) # Sleep when paused

def process_packet(packet):
    if not IS_SNIFFING: return # Double check
    if IP in packet:
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            length = len(packet)
            proto = "Other"
            port = 0
            risk = "Low"

            if TCP in packet:
                proto = "TCP"
                port = packet[TCP].dport
                # Simple Logic: Flag suspicious ports or flags for demo
                if port in [21, 22, 23, 3389] or packet[TCP].flags == 'S':
                    risk = "High" 
            elif UDP in packet:
                proto = "UDP"
                port = packet[UDP].dport
            
            socketio.emit('packet_data', {
                'time': datetime.now().strftime('%H:%M:%S'),
                'src': src,
                'dst': dst,
                'port': port,
                'proto': proto,
                'len': length,
                'risk': risk
            })
        except Exception as e:
            pass

#SOCKET EVENTS
@socketio.on('stop_sniffer')
def stop_sniffer():
    global IS_SNIFFING
    IS_SNIFFING = False
    print("[-] Sniffer Paused by User")

@socketio.on('start_sniffer')
def start_sniffer():
    global IS_SNIFFING
    IS_SNIFFING = True
    print("[+] Sniffer Resumed by User")

# --- ROUTES ---

@app.route('/live')
def live_monitor():
    global SNIFFING_THREAD, IS_SNIFFING
    IS_SNIFFING = True # Enable sniffing
    
    if SNIFFING_THREAD is None:
        SNIFFING_THREAD = threading.Thread(target=background_sniffer)
        SNIFFING_THREAD.daemon = True
        SNIFFING_THREAD.start()
    return render_template_string(LIVE_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_doc = mongo.db.users.find_one({"username": username})
        if user_doc and check_password_hash(user_doc['password'], password):
            user_obj = User(user_doc)
            login_user(user_obj)
            return redirect(url_for('history')) 
        else:
            flash('Invalid credentials')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if mongo.db.users.find_one({"username": username}):
            flash('Username taken')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        uid = mongo.db.users.insert_one({"username": username, "password": hashed_pw}).inserted_id
        user_obj = User({"_id": uid, "username": username, "password": hashed_pw})
        login_user(user_obj)
        return redirect(url_for('index'))
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/history')
@login_required
def history():
    scans = list(mongo.db.scans.find({"user_id": current_user.id}).sort("date", -1))
    return render_template_string(HISTORY_TEMPLATE, scans=scans)

@app.route('/', methods=['GET', 'POST'])
def index(): 
    results = None
    summary = {}
    
    if request.method == 'POST':
        f = request.files.get('pcap')
        if f and allowed_file(f.filename):
            filename = secure_filename(f.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(save_path)
            
            flow_df = extract_flows(save_path, out_csv=None)
            
            if flow_df is not None and not flow_df.empty:
                X = prepare_df(flow_df)
                if MODEL is None:
                    flash('Error: Model not loaded', 'error')
                    return redirect(url_for('index'))

                preds = MODEL.predict(X)
                probs = MODEL.predict_proba(X)
                
                rows = []
                attack_count = 0
                for i, row in flow_df.iterrows():
                    is_attack = int(preds[i])
                    if is_attack == 1: attack_count += 1
                    rows.append({
                        'src': row.get('src'), 'dst': row.get('dst'),
                        'proto': row.get('proto'),
                        'pred': is_attack, 'prob': float(probs[i][1])
                    })
                
                results = rows
                summary = {'attacks': attack_count, 'normal': len(rows)-attack_count, 'threat_level': (attack_count/len(rows))*100, 'total': len(rows)}
                
                if current_user.is_authenticated:
                    mongo.db.scans.insert_one({
                        "filename": filename,
                        "date": datetime.utcnow(),
                        "total_flows": len(rows),
                        "attacks_found": attack_count,
                        "threat_level": summary['threat_level'],
                        "user_id": current_user.id
                    })
            else:
                flash("No valid flows extracted.", "info")
        else:
            flash("Invalid file.", "error")

    return render_template_string(DASHBOARD_TEMPLATE, results=results, summary=summary, date_now=datetime.now().strftime("%Y-%m-%d %H:%M"))

if __name__ == "__main__":
    load_ml_model()
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)