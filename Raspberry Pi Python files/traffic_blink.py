import subprocess
import time
import RPi.GPIO as GPIO
import sys
from datetime import datetime

# GPIO setup
GREEN_LED_PIN = 18  # Traffic volume (physical pin 12)
RED_LED_PIN = 23    # High TCP traffic (physical pin 16)

def setup_leds():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(GREEN_LED_PIN, GPIO.OUT)
    GPIO.setup(RED_LED_PIN, GPIO.OUT)
    return GREEN_LED_PIN, RED_LED_PIN

def analyze_traffic(pcap_file):
    try:
        # Total packet count
        result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.number"], 
                                capture_output=True, text=True, check=True)
        total_packets = len(result.stdout.splitlines())
        
        # Protocol breakdown (TCP vs UDP)
        proto_result = subprocess.run(["tshark", "-r", pcap_file, "-qz", "io,phs"], 
                                      capture_output=True, text=True, check=True)
        tcp_count = udp_count = 0
        for line in proto_result.stdout.splitlines():
            if "tcp" in line.lower():
                tcp_count = int(line.split()[1]) if line.split()[1].isdigit() else 0
            elif "udp" in line.lower():
                udp_count = int(line.split()[1]) if line.split()[1].isdigit() else 0
        
        # Top source IPs
        ip_result = subprocess.run(["tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src", "-q", "-z", "conv,ip"], 
                                   capture_output=True, text=True, check=True)
        top_ip = "Unknown"
        for line in ip_result.stdout.splitlines():
            if "=>" in line and "Frames" not in line:
                top_ip = line.split()[0]  # First IP with traffic
                break
        
        print(f"Analysis for {pcap_file}:")
        print(f"Total packets: {total_packets}")
        print(f"TCP packets: {tcp_count} ({(tcp_count/total_packets)*100:.1f}%)")
        print(f"UDP packets: {udp_count} ({(udp_count/total_packets)*100:.1f}%)")
        print(f"Top source IP: {top_ip}")
        
        return total_packets, tcp_count / total_packets if total_packets > 0 else 0, top_ip
    except subprocess.CalledProcessError as e:
        print(f"Error analyzing file {pcap_file}: {e}")
        return 0, 0, "Unknown"
    except FileNotFoundError:
        print("tshark not found. Please install it with 'sudo apt install tshark'.")
        return 0, 0, "Unknown"

def blink_leds(green_pin, red_pin, total_packets, tcp_ratio):
    # Green LED: Traffic volume
    if total_packets > 100:  # High traffic
        green_interval = 0.2
        print("High traffic detected - Fast green blinking")
    elif total_packets > 50:  # Medium traffic
        green_interval = 0.5
        print("Medium traffic detected - Medium green blinking")
    else:  # Low traffic
        green_interval = 1.0
        print("Low traffic detected - Slow green blinking")
    
    # Red LED: High TCP traffic (>70%)
    red_on = tcp_ratio > 0.7
    if red_on:
        print("High TCP traffic (>70%) - Red LED on")
    
    # Blink sequence (5 cycles)
    for _ in range(5):
        GPIO.output(green_pin, GPIO.HIGH)
        if red_on:
            GPIO.output(red_pin, GPIO.HIGH)
        time.sleep(green_interval)
        GPIO.output(green_pin, GPIO.LOW)
        if red_on:
            GPIO.output(red_pin, GPIO.LOW)
        time.sleep(green_interval)

def log_results(pcap_file, total_packets, tcp_ratio, top_ip):
    with open("/home/Mathi.b_417/traffic_log.txt", "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} | File: {pcap_file} | Packets: {total_packets} | TCP%: {tcp_ratio*100:.1f} | Top IP: {top_ip}\n")
    print("Results logged to traffic_log.txt")

def main(file_id):
    from download_from_drive import download_from_drive
    
    downloaded_file = download_from_drive(file_id)
    if not downloaded_file:
        print("Download failed. Exiting.")
        return
    
    try:
        total_packets, tcp_ratio, top_ip = analyze_traffic(downloaded_file)
        if total_packets == 0:
            print("No packets to analyze. Exiting.")
        else:
            green_pin, red_pin = setup_leds()
            blink_leds(green_pin, red_pin, total_packets, tcp_ratio)
            log_results(downloaded_file, total_packets, tcp_ratio, top_ip)
    except KeyboardInterrupt:
        print("Stopped by user")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        GPIO.cleanup()
        print("GPIO cleaned up")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 traffic_blink.py <file_id>")
        sys.exit(1)
    file_id = sys.argv[1]
    main(file_id)