import subprocess
import time
import os
import csv
from datetime import datetime

def get_tshark_interfaces():
    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)
        interfaces = result.stdout.splitlines()
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return []
    except FileNotFoundError:
        print("tshark not found. Please install Wireshark and ensure 'tshark' is in your PATH.")
        return []

def capture_packets(interface, duration=10, output_dir="captures"):
    timestamp = datetime.now().strftime("%H%M%S_%d%m%Y")
    output_file = os.path.join(output_dir, f"capture_{timestamp}.pcap")
    try:
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", output_file], check=True)
        print(f"Packets captured and saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets: {e}")
        return None

def save_to_csv(csv_path, total_packets, tcp_ratio, udp_ratio, other_ratio, top_ip):
    file_exists = os.path.isfile(csv_path)
    with open(csv_path, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "total_packets", "tcp_ratio", "udp_ratio", "other_ratio", "top_ip"])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, total_packets, tcp_ratio, udp_ratio, other_ratio, top_ip])

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
        
        top_ip = "Unknown"
        ip_result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src", "-q", "-z", "conv,ip"], 
                                   capture_output=True, text=True, check=True)
        for line in ip_result.stdout.splitlines():
            if "=>" in line and "Frames" not in line:
                top_ip = line.split()[0]
                break
        
        print(f"\nAnalysis for {pcap_file}:")
        print(f"Total packets: {total_packets}")
        print(f"TCP packets: {tcp_count} ({(tcp_count/total_packets)*100:.1f}%)")
        print(f"UDP packets: {udp_count} ({(udp_count/total_packets)*100:.1f}%)")
        print(f"Other packets: {other_count} ({(other_count/total_packets)*100:.1f}%)")
        print(f"Top source IP: {top_ip}")
        
        return total_packets, tcp_count / total_packets if total_packets > 0 else 0, top_ip
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing file {pcap_file}: {e}")
        return 0, 0, "Unknown"

def log_results(pcap_file, total_packets, tcp_ratio, top_ip, avg_packets=None, avg_tcp_ratio=None):
    with open("traffic_log.txt", "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if avg_packets is None:
            log.write(f"{timestamp} | File: {pcap_file} | Packets: {total_packets} | TCP%: {tcp_ratio*100:.1f} | Top IP: {top_ip}\n")
        else:
            log.write(f"{timestamp} | Avg Packets: {avg_packets:.1f} | Avg TCP%: {avg_tcp_ratio*100:.1f} | Last File: {pcap_file} | Last Packets: {total_packets} | Last TCP%: {tcp_ratio*100:.1f} | Top IP: {top_ip}\n")
    print("Results logged to traffic_log.txt")


def main():
    try:
        interfaces = get_tshark_interfaces()
        if not interfaces:
            print("No network interfaces found. Exiting.")
            return
        
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        
        choice = int(input("Select interface number: ")) - 1
        if not 0 <= choice < len(interfaces):
            print("Invalid interface number.")
            return
        
        interface = interfaces[choice].split()[1].split("(")[0]
        
        # Create a timestamped folder to save all .pcap files for this run
        run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        #output_dir = os.path.join(r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\Captured Packets", run_timestamp)
        output_dir = os.path.join(r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\Captured Packets", run_timestamp)
        os.makedirs(output_dir, exist_ok=True)
        print(f"\nCaptures will be saved to: {output_dir}\n")

        print("Starting 10 periodic captures for averaging...")
        packet_counts = []
        tcp_ratios = []
        last_top_ip = "Unknown"
        last_file = None
        
        for i in range(5):
            print(f"\nSample {i+1}/10")
            captured_file = capture_packets(interface, duration=10, output_dir=output_dir)
            if captured_file:
                total_packets, tcp_ratio, top_ip = analyze_traffic(captured_file)
                if total_packets > 0:
                    udp_ratio = 0.0
                    other_ratio = 0.0
                    if tcp_ratio < 1.0:
                        udp_ratio = (1.0 - tcp_ratio) * 0.7  # Assumed distribution if no exact UDP
                        other_ratio = 1.0 - tcp_ratio - udp_ratio
                    
                    packet_counts.append(total_packets)
                    tcp_ratios.append(tcp_ratio)
                    last_top_ip = top_ip
                    last_file = captured_file
                    log_results(captured_file, total_packets, tcp_ratio, top_ip)
                    
                    # ✅ Save to CSV
                    #csv_path = os.path.join(r"F:\Spark\Spark Individual\Packet Capture Files\Home_wifi\traffic_data", run_timestamp+"_traffic_data.csv")
                    csv_path = os.path.join(r"F:\Spark\Spark Individual\Packet Capture Files\Uni_wifi\traffic_data", run_timestamp+"_traffic_data.csv")
                    save_to_csv(csv_path, total_packets, tcp_ratio, udp_ratio, other_ratio, top_ip)

                
                else:
                    print("No packets captured in this sample.")
            time.sleep(2)
        
        if packet_counts:
            avg_packets = sum(packet_counts) / len(packet_counts)
            avg_tcp_ratio = sum(tcp_ratios) / len(tcp_ratios)
            print(f"\n--- Summary ---")
            print(f"Average packets: {avg_packets:.1f}")
            print(f"Average TCP ratio: {avg_tcp_ratio*100:.1f}%")

            if avg_packets > 1000:
                print("Traffic Volume: HIGH")
            elif avg_packets > 250:
                print("Traffic Volume: MEDIUM")
            else:
                print("Traffic Volume: LOW")
            
            if avg_tcp_ratio > 0.7:
                print("⚠️  High TCP dominance detected!")

            log_results(last_file, packet_counts[-1], tcp_ratios[-1], last_top_ip, avg_packets, avg_tcp_ratio)
        else:
            print("No valid samples collected.")
        
    except ValueError:
        print("Please enter a valid number.")
    except KeyboardInterrupt:
        print("Stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
