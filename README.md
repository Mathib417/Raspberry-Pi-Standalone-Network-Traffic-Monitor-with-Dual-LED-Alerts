# Raspberry Pi Standalone Network Traffic Monitor with Dual-LED Alerts

---

## 📡 Overview

This project creates a **standalone network traffic monitoring system** using a **Raspberry Pi**. It captures packets periodically, analyzes them, and gives **LED feedback** based on the traffic:

- 🟢 **Green LED** blinks to show **average packet volume**:
  - Slow (10s blink) → ≤250 packets
  - Medium (5s blink) → 251–1000 packets
  - Fast (2s blink) → >1000 packets
- 🔴 **Red LED** turns ON if **TCP traffic >70%** (shows TCP dominance)

Results are **logged locally**, making this a great embedded systems + IoT mini-project.

---

## ✨ Features

- ⏱️ **10x Periodic Packet Captures** (10 seconds each)
- 📊 **Traffic Analysis**: total packets, TCP/UDP count, top source IP
- 🔦 **LED Feedback** via GPIO
- 📁 **Local Logging**: Saved to `/home/Mathi.b_417/traffic_log.txt`

---

## 🔧 Prerequisites

### Software

```bash
sudo apt update
sudo apt install tshark -y
sudo pip3 install RPi.GPIO
```

- Raspberry Pi OS (tested on **Lite Bookworm**)
- `tshark` (for packet capture)
- `RPi.GPIO` (for controlling LEDs)
- Python 3 (pre-installed)

### Hardware

- **Raspberry Pi** (e.g., Pi 4)
- **Green LED** → GPIO 18 (pin 12)
- **Red LED** → GPIO 23 (pin 16)
- 220Ω–330Ω resistors
- Breadboard + Jumper wires

### Wiring

```
GPIO 18 (Pin 12) ---> [Green LED +] ---> [220Ω] ---> GND (Pin 6)
GPIO 23 (Pin 16) ---> [Red LED +] ---> [220Ω] ---> GND (Pin 6)
```

---

## 📥 Installation

```bash
git clone https://github.com/Mathib417/raspberry-pi-traffic-monitor.git
cd raspberry-pi-traffic-monitor
```

> Optional (for tshark):
```bash
sudo usermod -a -G wireshark Mathi.b_417
```

> Virtual environment (optional):
```bash
python3 -m venv myenv
source myenv/bin/activate
```

---

## ▶️ Usage

Run the script:

```bash
python3 traffic_monitor_pi.py
# or (with sudo if required)
sudo python3 traffic_monitor_pi.py
```

Follow the prompts:

- Choose your network interface (e.g., `wlan0`)
- Wait for 10 samples to complete

---

## 🔍 What Happens

- 10 captures (10 seconds each, 2s delay)
- Results analyzed and logged
- **Green LED** blinks based on average packet count
- **Red LED** turns on if TCP traffic is dominant (>70%)

---

## 📄 Check Logs

```bash
cat /home/Mathi.b_417/traffic_log.txt
```

---

## 📂 File Structure

```
raspberry-pi-traffic-monitor/
├── traffic_monitor_pi.py  # Main script
├── traffic_log.txt        # Output log file
└── README.md              # Project description
```

---

## 🧪 Example Output

```
1. wlan0
2. any
3. lo (Loopback)
4. eth0
5. bluetooth0
6. bluetooth-monitor
7. nflog
8. nfqueue
9. dbus-system
10. dbus-session
11. ciscodump (Cisco remote capture)
12. dpauxmon (DisplayPort AUX channel monitor capture)
13. randpkt (Random packet generator)
14. sdjournal (systemd Journal Export)
15. sshdump (SSH remote capture)
16. udpdump (UDP Listener remote capture)
17. wifidump (Wi-Fi remote capture)
Select interface number: 1

Starting 10 periodic captures for averaging...

Sample 1/10
Packets captured and saved to /home/Mathi.b_417/capture_142345_22032025.pcap
Analysis for capture:
Total packets: 1200
TCP packets: 900 (75.0%)
UDP packets: 200 (16.7%)
Other packets: 100 (8.3%)
Top source IP: 192.168.23.1

[... 9 more samples ...]

Averaged over 10 samples:
Average packets: 1175.0
Average TCP ratio: 74.5%
Green LED: fast blinking (2s)
Red LED: ON (TCP >70%)
Results logged to /home/Mathi.b_417/traffic_log.txt
GPIO cleaned up
```

---

## 🛠️ Troubleshooting

- ❌ **"tshark not found"** → Run: `sudo apt install tshark`
- ❌ **Permission issues** → Run with `sudo` or update group
- ❌ **No packets?** → Check interface is active (`ifconfig`)
- ❌ **LEDs not working?** → Recheck wiring and GPIO pin numbers

---

## 🌱 Future Enhancements

- **ML Model** : Integrate a machine learning model to predict traffic patterns or detect anomalies based on historical packet data, enhancing the system’s intelligence.
- **More User-Friendly Feedback (Buzzer, LED)** : Add a buzzer for audible alerts (e.g., beeping for high traffic) and extend LED feedback (e.g., more colors or patterns) for intuitive real-time notifications.
- **Cloud Upload** : Enable uploading of .pcap files and logs to a cloud service for remote access and long-term storage.

---

## 🤝 Contributing

Pull requests are welcome! Fork the repo and feel free to:
- Fix bugs
- Improve features
- Add suggestions

---

## 🙏 Acknowledgments

- Special thanks to **tshark** and the **Raspberry Pi** community ❤️
```
