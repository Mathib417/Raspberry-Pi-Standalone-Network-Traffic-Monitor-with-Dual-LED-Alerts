# train_model.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

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

    # Save model and scaler
    joblib.dump(model, "anomaly_model.pkl")
    joblib.dump(scaler, "anomaly_scaler.pkl")
    print("✅ Model and scaler saved as 'anomaly_model.pkl' and 'anomaly_scaler.pkl'")

    # Display quick summary
    counts = df['anomaly'].value_counts()
    print(f"\nAnomaly Detection Summary:\nNormal: {counts.get(1,0)}\nAnomalies: {counts.get(-1,0)}")

# ✏️ Set this to your actual CSV file path
if __name__ == "__main__":
    csv_path = input("Enter path to traffic_data.csv: ").strip().strip('"')
    train_model(csv_path)

