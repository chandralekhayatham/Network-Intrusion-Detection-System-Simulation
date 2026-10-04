from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

FEATURES = [
    'source_port','destination_port','packet_count','byte_count','duration_seconds',
    'connection_count','failed_connection_count','syn_count','rst_count','average_packet_size'
]


def train_and_evaluate(csv_path='data/network_traffic.csv', model_path='ml/ids_model.joblib', metrics_path='ml/metrics.json'):
    df = pd.read_csv(csv_path)
    X = df[FEATURES].fillna(0)
    y = df['label'].map({'NORMAL': 0, 'SUSPICIOUS': 1})
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    cm = confusion_matrix(y_test, pred).tolist()
    metrics = {
        'accuracy': round(accuracy_score(y_test, pred), 4),
        'precision': round(precision_score(y_test, pred, zero_division=0), 4),
        'recall': round(recall_score(y_test, pred, zero_division=0), 4),
        'f1': round(f1_score(y_test, pred, zero_division=0), 4),
        'confusion_matrix': cm,
        'test_records': int(len(y_test)),
        'features': FEATURES,
        'model': 'RandomForestClassifier'
    }
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    Path(metrics_path).write_text(json.dumps(metrics, indent=2), encoding='utf-8')
    return metrics


def predict_ml(flow, model_path='ml/ids_model.joblib'):
    model = joblib.load(model_path)
    row = pd.DataFrame([{k: flow.get(k, 0) for k in FEATURES}])
    probability = float(model.predict_proba(row)[0][1])
    return round(probability * 100, 2)
