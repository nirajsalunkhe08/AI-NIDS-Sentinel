import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# 1. Generate Synthetic Traffic Data (The "Brain" Knowledge)
def generate_live_data():
    # --- NORMAL TRAFFIC (Web, DNS, HTTPS) ---
    # Low ports (80, 443), moderate packet sizes
    n_normal = 2000
    normal_data = {
        'sport': np.random.randint(1024, 65535, n_normal), # Random ephemeral ports
        'dport': np.random.choice([80, 443, 53, 8080], n_normal),
        'len': np.random.randint(50, 1500, n_normal),
        'proto': np.random.choice([6, 17], n_normal), # TCP/UDP
        'label': 0 # 0 = Safe
    }

    # --- ATTACK TRAFFIC (Scanning, Telnet, Suspicious) ---
    # Suspicious ports (21, 22, 23, 3389), weird sizes (too small/big)
    n_attack = 2000
    attack_data = {
        'sport': np.random.randint(1024, 65535, n_attack),
        'dport': np.random.choice([21, 22, 23, 3389, 445, 135], n_attack), # Telnet, SSH, RDP, SMB
        'len': np.random.choice([0, 1, 2, 8000], n_attack), # Anomalous sizes
        'proto': np.random.choice([6, 17], n_attack),
        'label': 1 # 1 = Threat
    }

    df_norm = pd.DataFrame(normal_data)
    df_attk = pd.DataFrame(attack_data)
    
    # Combine and Shuffle
    return pd.concat([df_norm, df_attk]).sample(frac=1).reset_index(drop=True)

# 2. Train the Model
print("[-] Generaring training data...")
df = generate_live_data()

X = df[['sport', 'dport', 'len', 'proto']]
y = df['label']

print("[-] Training Random Forest...")
clf = RandomForestClassifier(n_estimators=50, random_state=42)
clf.fit(X, y)

# 3. Save the Model
joblib.dump(clf, 'live_model.joblib')
print("[+] DONE. 'live_model.joblib' saved.")
print(f"    - Accuracy on training set: {clf.score(X, y)*100:.2f}%")