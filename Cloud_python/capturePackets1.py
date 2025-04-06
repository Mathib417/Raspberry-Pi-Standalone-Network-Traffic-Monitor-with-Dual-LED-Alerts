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
        # Extract the actual device name (e.g., \Device\NPF_{...})
        device_name = interface.split()[1]  # Take the second part after splitting
        subprocess.run(["tshark", "-i", device_name, "-a", f"duration:{duration}", "-w", output_file], check=True)
        print(f"Packets captured and saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets: {e}")
    except IndexError:
        print("Error: Could not parse interface name.")

if __name__ == "__main__":
    interfaces = get_tshark_interfaces()
    if interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        try:
            choice = int(input("Select interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                capture_packets(interfaces[choice], duration=10)
            else:
                print("Invalid interface number.")
        except ValueError:
            print("Please enter a valid number.")
    else:
        print("No interfaces found.")