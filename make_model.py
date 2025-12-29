import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib


data = {
    'sport': [443, 80, 53, 22],
    'dport': [5555, 1234, 53, 80],
    'proto': [6, 6, 17, 6],
    'pkt_count': [10, 100, 2, 5],
    'byte_count': [1000, 50000, 200, 500],
    'duration': [1.5, 5.0, 0.1, 0.5],
    'bpk': [600.0, 10000.0, 100.0, 100.0],
    'mean_pkt_size': [100.0, 500.0, 100.0, 100.0],
    'std_pkt_size': [10.0, 50.0, 0.0, 5.0],
    'syn_count': [1, 10, 0, 1],
    'fin_count': [1, 10, 0, 1],
    'ack_count': [5, 50, 0, 2],
    'pkt_per_sec': [6.6, 20.0, 20.0, 10.0],
    'byte_per_pkt': [100.0, 500.0, 100.0, 100.0],
    'label': [0, 1, 0, 0]  # 0=Normal, 1=Attack
}

print("[*] Creating dummy training data...")
df = pd.DataFrame(data)

#Prepare X (features) and y (labels)
# We select only numeric types and drop the label for X
X = df.select_dtypes(include=[np.number]).drop(columns=['label'])
y = df['label']

#Train the model
print("[*] Training RandomForest model...")
clf = RandomForestClassifier(n_estimators=10, random_state=42)
clf.fit(X, y)

#Save the model AND the column names
output_file = "nids_model.joblib"
print(f"[*] Saving model to {output_file}...")
joblib.dump({'model': clf, 'columns': X.columns.tolist()}, output_file)

print(f"[+] Done! {output_file} created. You can now run 'python app.py'")