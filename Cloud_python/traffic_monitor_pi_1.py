import subprocess
import time
import RPi.GPIO as GPIO
from datetime import datetime

# GPIO setup
GREEN_LED_PIN = 18  # Traffic volume (pin 12)
RED_LED_PIN = 23    # High TCP traffic (pin 16)
BUTTON_PIN = 24     # Button to start/stop (pin 18)
BUZZER_PIN = 25     # Buzzer for high traffic (pin 22)

def setup_gpio():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(GREEN_LED_PIN, GPIO.OUT)
    GPIO.setup(RED_LED_PIN, GPIO.OUT)
    GPIO.setup(BUZZER_PIN, GPIO.OUT)
    GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)  # Button with pull-up resistor
    return GREEN_LED_PIN, RED_LED_PIN, BUZZER_PIN, BUTTON_PIN

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
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", output_file], check=True)
        print(f"Packets captured and saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets: {e}")
        return None

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
        print("tshark not found.")
        return 0, 0, "Unknown"

def blink_leds_and_buzz(green_pin, red_pin, buzzer_pin, total_packets, tcp_ratio):
    if total_packets > 100:
        green_interval = 0.2
        print("High traffic detected - Fast green blinking")
        buzz = True  # Trigger buzzer for high traffic
    elif total_packets > 50:
        green_interval = 0.5
        print("Medium traffic detected - Medium green blinking")
        buzz = False
    else:
        green_interval = 1.0
        print("Low traffic detected - Slow green blinking")
        buzz = False
    
    red_on = tcp_ratio > 0.7
    if red_on:
        print("High TCP traffic (>70%) - Red LED on")
    
    for _ in range(5):
        GPIO.output(green_pin, GPIO.HIGH)
        if red_on:
            GPIO.output(red_pin, GPIO.HIGH)
        if buzz:
            GPIO.output(buzzer_pin, GPIO.HIGH)  # Beep on
        time.sleep(green_interval)
        GPIO.output(green_pin, GPIO.LOW)
        if red_on:
            GPIO.output(red_pin, GPIO.LOW)
        if buzz:
            GPIO.output(buzzer_pin, GPIO.LOW)  # Beep off
        time.sleep(green_interval)

def log_results(pcap_file, total_packets, tcp_ratio, top_ip):
    with open("/home/Mathi.b_417/traffic_log.txt", "a") as log:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log.write(f"{timestamp} | File: {pcap_file} | Packets: {total_packets} | TCP%: {tcp_ratio*100:.1f} | Top IP: {top_ip}\n")
    print("Results logged to /home/Mathi.b_417/traffic_log.txt")

def main():
    green_pin, red_pin, buzzer_pin, button_pin = setup_gpio()
    monitoring = False  # Start with monitoring off
    
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
        
        interface = interfaces[choice].split()[1].split("(")[0]  # e.g., wlan0
        
        print("Press the button (GPIO 24) to start/stop monitoring. Ctrl+C to exit.")
        
        while True:
            # Check button state (LOW when pressed due to pull-up)
            if GPIO.input(button_pin) == GPIO.LOW and not monitoring:
                print("Button pressed - Starting monitoring...")
                monitoring = True
                time.sleep(0.3)  # Debounce delay
            elif GPIO.input(button_pin) == GPIO.LOW and monitoring:
                print("Button pressed - Stopping monitoring...")
                monitoring = False
                time.sleep(0.3)  # Debounce delay
            
            if monitoring:
                captured_file = capture_packets(interface, duration=10)
                if captured_file:
                    total_packets, tcp_ratio, top_ip = analyze_traffic(captured_file)
                    if total_packets > 0:
                        blink_leds_and_buzz(green_pin, red_pin, buzzer_pin, total_packets, tcp_ratio)
                        log_results(captured_file, total_packets, tcp_ratio, top_ip)
                    else:
                        print("No packets captured or analyzed.")
                time.sleep(5)  # Wait before next capture in continuous mode
            else:
                time.sleep(0.1)  # Reduce CPU usage when idle
    
    except KeyboardInterrupt:
        print("Stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        GPIO.cleanup()
        print("GPIO cleaned up")

if __name__ == "__main__":
    main()