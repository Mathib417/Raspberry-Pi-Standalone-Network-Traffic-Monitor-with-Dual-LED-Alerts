import subprocess
import time
import os
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ==== CONFIG ====
INTERFACE_NAME = "Wi-Fi"  # Replace with your interface name like "eth0" or "wlan0"
CAPTURE_DURATION = 10     # Duration in seconds per capture
CAPTURE_COUNT = 5         # How many times to capture
'''
#Home Wifi
OUTPUT_BASE_DIR = r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\Realtime Captures"
MODEL_PATH = r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\traffic_data\anomaly_model_latest.pkl"
SCALER_PATH = r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\traffic_data\anomaly_scaler_latest.pkl"
'''

#Uni WiFi
OUTPUT_BASE_DIR = r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\Realtime Captures"
MODEL_PATH = r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\traffic_data\anomaly_model_latest.pkl"
SCALER_PATH = r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\traffic_data\anomaly_scaler_latest.pkl"
# ===============

def capture_packets(interface, duration, output_dir):
    timestamp = datetime.now().strftime("%H%M%S_%d%m%Y")
    filename = f"capture_{timestamp}.pcap"
    filepath = os.path.join(output_dir, filename)
    try:
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", filepath], check=True)
        print(f"✅ Captured: {filepath}")
        return filepath, timestamp
    except subprocess.CalledProcessError as e:
        print(f"❌ Capture error: {e}")
        return None, None

def analyze_traffic(pcap_file):
    try:
        result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"],
                                capture_output=True, text=True, check=True)
        total_packets = len(result.stdout.splitlines())

        proto_result = subprocess.run(["tshark", "-r", pcap_file, "-qz", "io,phs"],
                                      capture_output=True, text=True, check=True)
        tcp_count = udp_count = 0
        for line in proto_result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and "tcp" in parts[0].lower():
                tcp_count = int(parts[1]) if parts[1].isdigit() else 0
            elif len(parts) >= 2 and "udp" in parts[0].lower():
                udp_count = int(parts[1]) if parts[1].isdigit() else 0

        if tcp_count == 0 and udp_count == 0 and total_packets > 0:
            proto_fallback = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.proto"],
                                            capture_output=True, text=True, check=True)
            proto_lines = proto_fallback.stdout.splitlines()
            tcp_count = sum(1 for line in proto_lines if line.strip() == "6")
            udp_count = sum(1 for line in proto_lines if line.strip() == "17")

        other_count = total_packets - (tcp_count + udp_count)
        return total_packets, tcp_count, udp_count, other_count
    except Exception as e:
        print(f"❌ Analysis error: {e}")
        return 0, 0, 0, 0

def detect_anomaly(model, scaler, features):
    try:
        X_scaled = scaler.transform([features])
        result = model.predict(X_scaled)[0]
        return result  # -1 = anomaly, 1 = normal
    except Exception as e:
        print(f"❌ Detection error: {e}")
        return 1  # Assume normal if error

def main():
    # Load model and scaler
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print("❌ Required .pkl files not found. Train the model first.")
        return

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("✅ Loaded trained model and scaler.")

    timestamp_folder = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(OUTPUT_BASE_DIR, timestamp_folder)
    os.makedirs(output_dir, exist_ok=True)

    for i in range(CAPTURE_COUNT):
        print(f"\n📡 Capture {i+1}/{CAPTURE_COUNT}")
        pcap_file, ts = capture_packets(INTERFACE_NAME, CAPTURE_DURATION, output_dir)
        if not pcap_file:
            continue

        total, tcp, udp, other = analyze_traffic(pcap_file)
        if total == 0:
            print("⚠️ No packets captured.")
            continue

        tcp_ratio = tcp / total
        udp_ratio = udp / total
        other_ratio = other / total

        print(f"📊 Packets: {total} | TCP: {tcp_ratio:.2f} | UDP: {udp_ratio:.2f} | Other: {other_ratio:.2f}")

        prediction = detect_anomaly(model, scaler, [total, tcp_ratio, udp_ratio, other_ratio])
        if prediction == -1:
            print("⚠️  Anomaly Detected! This sample is suspicious.")
        else:
            print("✅ Normal traffic.")

        time.sleep(2)

if __name__ == "__main__":
    main()
