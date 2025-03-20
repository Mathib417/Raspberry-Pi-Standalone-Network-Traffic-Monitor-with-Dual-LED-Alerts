import subprocess
import time
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os

# Update scope to allow file creation
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

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
        device_name = interface.split()[1]  # Extract the device name
        subprocess.run(["tshark", "-i", device_name, "-a", f"duration:{duration}", "-w", output_file], check=True)
        print(f"Packets captured and saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets: {e}")
        return None

def authenticate():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    else:
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def upload_to_drive(file_path):
    creds = authenticate()
    service = build("drive", "v3", credentials=creds)
    file_metadata = {"name": os.path.basename(file_path)}  # Use the file's name
    media = MediaFileUpload(file_path, mimetype="application/octet-stream")
    file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
    print(f"Uploaded file ID: {file.get('id')}")
    return file.get("id")  # Return the file ID for later use

if __name__ == "__main__":
    # Step 1: Capture packets
    interfaces = get_tshark_interfaces()
    if interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        try:
            choice = int(input("Select interface number: ")) - 1
            if 0 <= choice < len(interfaces):
                captured_file = capture_packets(interfaces[choice], duration=10)
                if captured_file:
                    # Step 2: Upload to Google Drive
                    file_id = upload_to_drive(captured_file)
                    print(f"File uploaded successfully with ID: {file_id}")
            else:
                print("Invalid interface number.")
        except ValueError:
            print("Please enter a valid number.")
    else:
        print("No interfaces found.")