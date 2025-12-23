import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("[-] 1. Generating 'Normal' Traffic Profiles...")
# PROFILE A: Web Browsing (HTTP/HTTPS)
# - Characteristics: Ports 80/443, more bytes received than sent, moderate duration
n_web = 1000
web_traffic = {
    'sport': np.random.randint(1024, 65535, n_web),
    'dport': np.random.choice([80, 443, 8080], n_web),
    'proto': [6] * n_web, # TCP
    'pkt_count': np.random.randint(20, 100, n_web),
    'byte_count': np.random.randint(10000, 500000, n_web), # Web pages are big
    'duration': np.random.uniform(1.0, 15.0, n_web),
    'bpk': np.zeros(n_web), # Calculated later
    'mean_pkt_size': np.random.uniform(500, 1200, n_web),
    'std_pkt_size': np.random.uniform(200, 500, n_web),
    'syn_count': np.random.randint(1, 2, n_web), # Normal handshake
    'fin_count': np.random.randint(1, 2, n_web),
    'ack_count': np.random.randint(20, 100, n_web),
    'pkt_per_sec': np.zeros(n_web), # Calculated later
    'byte_per_pkt': np.zeros(n_web), # Calculated later
    'label': [0] * n_web
}

# PROFILE B: DNS Queries (Normal background noise)
# - Characteristics: Port 53, UDP, tiny packets, very short
n_dns = 500
dns_traffic = {
    'sport': np.random.randint(1024, 65535, n_dns),
    'dport': [53] * n_dns,
    'proto': [17] * n_dns, # UDP
    'pkt_count': np.random.randint(2, 6, n_dns),
    'byte_count': np.random.randint(100, 500, n_dns),
    'duration': np.random.uniform(0.01, 0.1, n_dns),
    'bpk': np.zeros(n_dns),
    'mean_pkt_size': np.random.uniform(60, 150, n_dns),
    'std_pkt_size': np.random.uniform(0, 20, n_dns),
    'syn_count': [0] * n_dns, # UDP has no flags
    'fin_count': [0] * n_dns,
    'ack_count': [0] * n_dns,
    'pkt_per_sec': np.zeros(n_dns),
    'byte_per_pkt': np.zeros(n_dns),
    'label': [0] * n_dns
}

print("[-] 2. Generating 'Attack' Traffic Profiles...")
# PROFILE C: SYN Flood (DoS Attack)
# - Characteristics: High packet count, tiny size, SYN flag ONLY, no FIN
n_dos = 800
dos_attack = {
    'sport': np.random.randint(1024, 65535, n_dos),
    'dport': [80] * n_dos, # Targeting web server
    'proto': [6] * n_dos,
    'pkt_count': np.random.randint(1000, 10000, n_dos), # Massive packets
    'byte_count': np.random.randint(40000, 400000, n_dos), # But small size per packet
    'duration': np.random.uniform(5.0, 10.0, n_dos),
    'bpk': np.zeros(n_dos),
    'mean_pkt_size': np.random.uniform(40, 60, n_dos), # Tiny headers only
    'std_pkt_size': np.random.uniform(0, 5, n_dos),
    'syn_count': np.random.randint(1000, 10000, n_dos), # All SYNs
    'fin_count': [0] * n_dos,
    'ack_count': [0] * n_dos, # No ACKs (handshake never completes)
    'pkt_per_sec': np.zeros(n_dos),
    'byte_per_pkt': np.zeros(n_dos),
    'label': [1] * n_dos
}

# PROFILE D: Port Scan (Reconnaissance)
# - Characteristics: Connecting to random ports, 1-2 packets per flow, instant duration
n_scan = 800
scan_attack = {
    'sport': np.random.randint(1024, 65535, n_scan),
    'dport': np.random.randint(1, 10000, n_scan), # Random destination ports
    'proto': [6] * n_scan,
    'pkt_count': np.random.randint(1, 3, n_scan),
    'byte_count': np.random.randint(40, 120, n_scan),
    'duration': np.random.uniform(0.001, 0.01, n_scan), # Super fast
    'bpk': np.zeros(n_scan),
    'mean_pkt_size': np.random.uniform(40, 60, n_scan),
    'std_pkt_size': [0] * n_scan,
    'syn_count': np.random.randint(1, 2, n_scan),
    'fin_count': [0] * n_scan,
    'ack_count': [0] * n_scan,
    'pkt_per_sec': np.zeros(n_scan),
    'byte_per_pkt': np.zeros(n_scan),
    'label': [1] * n_scan
}

# 3. Merge and Calculate Derived Features
print("[-] 3. Merging and calculating derived features...")
df = pd.concat([
    pd.DataFrame(web_traffic),
    pd.DataFrame(dns_traffic),
    pd.DataFrame(dos_attack),
    pd.DataFrame(scan_attack)
])

# Recalculate derived columns based on the logic above
df['bpk'] = df['byte_count'] / (df['duration'] + 0.00001)
df['pkt_per_sec'] = df['pkt_count'] / (df['duration'] + 0.00001)
df['byte_per_pkt'] = df['byte_count'] / df['pkt_count']

# Shuffle the data
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# 4. Train
print(f"[-] 4. Training on {len(df)} realistic samples...")
X = df.drop(columns=['label'])
y = df['label']

# Split to test accuracy
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
clf.fit(X_train, y_train)

# 5. Evaluate
print("\n[+] Model Evaluation:")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# 6. Save
print("[-] Saving expert model to nids_model.joblib...")
joblib.dump({'model': clf, 'columns': X.columns.tolist()}, "nids_model.joblib")
print("[+] DONE. Your model is now an expert.")