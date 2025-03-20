from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os

# Define the scope for Google Drive API
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

# Authenticate and get credentials
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

# Upload a file to Google Drive
def upload_to_drive(file_path):
    creds = authenticate()
    service = build("drive", "v3", credentials=creds)

    file_metadata = {"name": os.path.basename(file_path)}
    media = MediaFileUpload(file_path, mimetype="application/octet-stream")
    
    file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
    print(f"Uploaded File ID: {file.get('id')}")

# Example Usage: Upload a file
upload_to_drive("capture.pcap")  # Change this to your file path
