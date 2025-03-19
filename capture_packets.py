import subprocess
import time

def get_tshark_interfaces():
    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)
        interfaces = result.stdout.splitlines()
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return []
    except FileNotFoundError:
        print("tshark not found. Ensure Wireshark is installed.")
        return []

def capture_packets(interface, duration=10, output_file="capture.pcap"):
    try:
        subprocess.run(["tshark", "-i", interface.split()[0], "-a", f"duration:{duration}", "-w", output_file], check=True)
        print(f"Packets captured and saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets: {e}")

if __name__ == "__main__":
    interfaces = get_tshark_interfaces()
    if interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        choice = int(input("Select interface number: ")) - 1
        capture_packets(interfaces[choice], duration=10)
    else:
        print("No interfaces found.")