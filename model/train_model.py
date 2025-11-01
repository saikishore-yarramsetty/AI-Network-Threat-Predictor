# model/train_model.py
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- STEP 1: Create or Load Dataset ----------
data = {
    'packet_length': [60, 1500, 500, 200, 70, 1200, 400, 100, 90, 600, 1300, 50],
    'tcp_flags': [2, 24, 16, 2, 2, 24, 16, 2, 2, 16, 24, 2],
    'src_port': [443, 80, 21, 22, 8080, 53, 25, 22, 443, 110, 80, 8080],
    'dst_port': [80, 443, 22, 8080, 53, 25, 110, 21, 22, 80, 443, 53],
    'packet_rate': [5, 50, 10, 8, 4, 60, 20, 6, 5, 25, 40, 7],
    'label': ['Normal', 'Malicious', 'Normal', 'Normal', 'Normal', 'Malicious',
              'Malicious', 'Normal', 'Normal', 'Malicious', 'Malicious', 'Normal']
}

df = pd.DataFrame(data)

# ---------- STEP 2: Split Data ----------
X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ---------- STEP 3: Train Model ----------
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_train, y_train)

# ---------- STEP 4: Evaluate ----------
y_pred = model.predict(X_test)
print("\n✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# ---------- STEP 5: Save Model ----------
os.makedirs(os.path.join(BASE_DIR), exist_ok=True)
MODEL_OUT = os.path.join(BASE_DIR, "model.pkl")
joblib.dump(model, MODEL_OUT)
print(f"\n💾 Model saved as {MODEL_OUT}")
