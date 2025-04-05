import subprocess

import time

import RPi.GPIO as GPIO

from datetime import datetime



# GPIO setup

GREEN_LED_PIN = 18  # Traffic volume (physical pin 12)

RED_LED_PIN = 23    # High TCP traffic (physical pin 16)



def setup_leds():

    GPIO.setmode(GPIO.BCM)

    GPIO.setup(GREEN_LED_PIN, GPIO.OUT)

    GPIO.setup(RED_LED_PIN, GPIO.OUT)

    return GREEN_LED_PIN, RED_LED_PIN



def get_tshark_interfaces():

    try:

        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)

        interfaces = result.stdout.splitlines()

        return interfaces

    except subprocess.CalledProcessError as e:

        print(f"Error running tshark: {e}")

        return []

    except FileNotFoundError:

        print("tshark not found. Please install it with 'sudo apt install tshark -y'.")

        return []



def capture_packets(interface, duration=10):

    timestamp = datetime.now().strftime("%H%M%S_%d%m%Y")

    output_file = f"/home/Mathi.b_417/capture_{timestamp}.pcap"

    try:

        # Use interface name directly (e.g., wlan0)

        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", output_file], check=True)

        print(f"Packets captured and saved to {output_file}")

        return output_file

    except subprocess.CalledProcessError as e:

        print(f"Error capturing packets: {e}")

        return None



def analyze_traffic(pcap_file):

    try:

        # Total packet count

        result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"], 

                                capture_output=True, text=True, check=True)

        total_packets = len(result.stdout.splitlines())

        

        # Protocol breakdown

        proto_result = subprocess.run(["tshark", "-r", pcap_file, "-qz", "io,phs"], 

                                      capture_output=True, text=True, check=True)

        tcp_count = udp_count = 0

        for line in proto_result.stdout.splitlines():

            parts = line.split()

            if len(parts) >= 2 and "tcp" in parts[0].lower():

                tcp_count = int(parts[1]) if parts[1].isdigit() else 0

            elif len(parts) >= 2 and "udp" in parts[0].lower():

                udp_count = int(parts[1]) if parts[1].isdigit() else 0

        

        # Fallback for TCP/UDP if io,phs fails

        if tcp_count == 0 and udp_count == 0 and total_packets > 0:

            proto_fallback = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.proto"], 

                                            capture_output=True, text=True, check=True)

            proto_lines = proto_fallback.stdout.splitlines()

            tcp_count = sum(1 for line in proto_lines if line.strip() == "6")

            udp_count = sum(1 for line in proto_lines if line.strip() == "17")

        

        other_count = total_packets - (tcp_count + udp_count)

        

        # Top source IP

        ip_result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src", "-q", "-z", "conv,ip"], 

                                   capture_output=True, text=True, check=True)

        top_ip = "Unknown"

        for line in ip_result.stdout.splitlines():

            if "=>" in line and "Frames" not in line:

                top_ip = line.split()[0]

                break

        

        print(f"Analysis for {pcap_file}:")

        print(f"Total packets: {total_packets}")

        print(f"TCP packets: {tcp_count} ({(tcp_count/total_packets)*100:.1f}%)")

        print(f"UDP packets: {udp_count} ({(udp_count/total_packets)*100:.1f}%)")

        print(f"Other packets: {other_count} ({(other_count/total_packets)*100:.1f}%)")

        print(f"Top source IP: {top_ip}")

        

        return total_packets, tcp_count / total_packets if total_packets > 0 else 0, top_ip

    except subprocess.CalledProcessError as e:

        print(f"Error analyzing file {pcap_file}: {e}")

        return 0, 0, "Unknown"

    except FileNotFoundError:

        print("tshark not found. Please install it.")

        return 0, 0, "Unknown"



def blink_leds(green_pin, red_pin, total_packets, tcp_ratio):

    if total_packets > 1000:

        green_interval = 0.2

        print("High traffic detected - Fast green blinking")

    elif total_packets > 250:

        green_interval = 0.5

        print("Medium traffic detected - Medium green blinking")

    else:

        green_interval = 1.0

        print("Low traffic detected - Slow green blinking")

    

    red_on = tcp_ratio > 0.7

    if red_on:

        print("High TCP traffic (>70%) - Red LED on")

    

    if red_on:

            GPIO.output(red_pin, GPIO.HIGH)

            

    for _ in range(5):

        GPIO.output(green_pin, GPIO.HIGH)

        if red_on:

            GPIO.output(red_pin, GPIO.HIGH)

        time.sleep(green_interval)

        GPIO.output(green_pin, GPIO.LOW)

        time.sleep(green_interval)

        

    

    if red_on:

        GPIO.output(red_pin, GPIO.LOW)

        



def log_results(pcap_file, total_packets, tcp_ratio, top_ip):

    with open("/home/Mathi.b_417/traffic_log.txt", "a") as log:

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        log.write(f"{timestamp} | File: {pcap_file} | Packets: {total_packets} | TCP%: {tcp_ratio*100:.1f} | Top IP: {top_ip}\n")

    print("Results logged to /home/Mathi.b_417/traffic_log.txt")



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

        if 0 <= choice < len(interfaces):

            # Extract interface name (e.g., wlan0)

            interface = interfaces[choice].split()[1].split("(")[0]  # Handles "1. wlan0 (Wi-Fi)"

            captured_file = capture_packets(interface, duration=10)

            if captured_file:

                total_packets, tcp_ratio, top_ip = analyze_traffic(captured_file)

                if total_packets > 0:

                    green_pin, red_pin = setup_leds()

                    blink_leds(green_pin, red_pin, total_packets, tcp_ratio)

                    log_results(captured_file, total_packets, tcp_ratio, top_ip)

                else:

                    print("No packets captured or analyzed.")

        else:

            print("Invalid interface number.")

    except ValueError:

        print("Please enter a valid number.")

    except KeyboardInterrupt:

        print("Stopped by user.")

    except Exception as e:

        print(f"An error occurred: {e}")

    finally:

        GPIO.cleanup()

        print("GPIO cleaned up")



if __name__ == "__main__":

    main()

