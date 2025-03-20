import subprocess
import time
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os
from datetime import datetime

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

def capture_packets(interface, duration=10):
    timestamp = datetime.now().strftime("%d%m%Y%H%M%S")
    output_file = f"capture{timestamp}.pcap"
    try:
        device_name = interface.split()[1]
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

def get_or_create_folder_id(service, folder_name="Packet Capturer"):
    # Search for the folder
    query = f"mimeType='application/vnd.google-apps.folder' and name='{folder_name}'"  # Corrected query
    try:
        results = service.files().list(q=query, spaces='drive', fields="files(id, name)").execute()
        items = results.get("files", [])
        if items:
            print(f"Found folder: {items[0]['name']} (ID: {items[0]['id']})")
            return items[0]["id"]
        else:
            # Create the folder if it doesn’t exist
            print(f"Folder '{folder_name}' not found. Creating it...")
            file_metadata = {
                "name": folder_name,
                "mimeType": "application/vnd.google-apps.folder"
            }
            folder = service.files().create(body=file_metadata, fields="id").execute()
            folder_id = folder.get("id")
            print(f"Created folder '{folder_name}' with ID: {folder_id}")
            return folder_id
    except Exception as e:
        print(f"Error searching or creating folder: {e}")
        return None

def upload_to_drive(file_path, folder_id=None):
    creds = authenticate()
    service = build("drive", "v3", credentials=creds)
    file_metadata = {"name": os.path.basename(file_path)}
    if folder_id:
        file_metadata["parents"] = [folder_id]
    media = MediaFileUpload(file_path, mimetype="application/octet-stream")
    file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
    print(f"Uploaded file ID: {file.get('id')}")
    return file.get("id")

if __name__ == "__main__":
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
                    creds = authenticate()
                    service = build("drive", "v3", credentials=creds)
                    folder_id = get_or_create_folder_id(service, "Packet Capturer")  # Updated function name
                    if folder_id:
                        file_id = upload_to_drive(captured_file, folder_id)
                        print(f"File uploaded successfully with ID: {file_id} to 'Packet Capturer' folder")
                    else:
                        print("Upload failed due to folder issue.")
            else:
                print("Invalid interface number.")
        except ValueError:
            print("Please enter a valid number.")
    else:
        print("No interfaces found.")