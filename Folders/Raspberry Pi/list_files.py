from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

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

def list_files():
    creds = authenticate()
    service = build("drive", "v3", credentials=creds)

    results = service.files().list(pageSize=10, fields="files(id, name)").execute()
    items = results.get("files", [])

    if not items:
        print("No files found.")
    else:
        for item in items:
            print(f"{item['name']} ({item['id']})")

list_files()  # Lists the files on your Google Drive

