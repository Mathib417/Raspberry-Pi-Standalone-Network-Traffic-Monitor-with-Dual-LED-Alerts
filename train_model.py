# train_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
from datetime import datetime

timestamp = datetime.now().strftime("%H%M%S_%d%m%Y")

def train_model(csv_path):
    if not os.path.exists(csv_path):
        print("CSV file not found!")
        return

    # Load data
    df = pd.read_csv(csv_path)

    # Drop timestamp and IP (not used for now)
    features = df[["total_packets", "tcp_ratio", "udp_ratio", "other_ratio"]]

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    # Train Isolation Forest
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_scaled)

    # Predict
    df['anomaly'] = model.predict(X_scaled)  # 1 = normal, -1 = anomaly

    # Save results
    output_file = csv_path.replace(".csv", "_labeled.csv")
    df.to_csv(output_file, index=False)
    print(f"✅ Results with anomalies saved to: {output_file}")

    # Save model and scaler with timestamp + latest version
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir_latest = os.path.dirname(csv_path)
    #model_dir = r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\anomals"
    model_dir = r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\anomals"

    model_path = os.path.join(model_dir, f"anomaly_model_{timestamp}.pkl")
    scaler_path = os.path.join(model_dir, f"anomaly_scaler_{timestamp}.pkl")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    joblib.dump(model, os.path.join(model_dir_latest, "anomaly_model_latest.pkl"))
    joblib.dump(scaler, os.path.join(model_dir_latest, "anomaly_scaler_latest.pkl"))

    print(f"✅ Model saved as: {model_path}")
    print(f"✅ Scaler saved as: {scaler_path}")
    print("✅ Also updated: anomaly_model_latest.pkl and anomaly_scaler_latest.pkl")


    # Display quick summary
    counts = df['anomaly'].value_counts()
    print(f"\nAnomaly Detection Summary:\nNormal: {counts.get(1,0)}\nAnomalies: {counts.get(-1,0)}")

# ✏️ Set this to your actual CSV file path
if __name__ == "__main__":
    csv_path = input("Enter path to traffic_data.csv: ").strip().strip('"')
    train_model(csv_path)


