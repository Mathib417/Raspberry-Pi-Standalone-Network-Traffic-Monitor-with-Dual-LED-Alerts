from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import os

SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def download_from_drive(file_id, output_file="downloaded.pcap"):
    try:
        # Load credentials from token.json
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        service = build("drive", "v3", credentials=creds)
        
        # Request the file
        request = service.files().get_media(fileId=file_id)
        with open(output_file, "wb") as f:
            downloader = MediaIoBaseDownload(f, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                print(f"Download {int(status.progress() * 100)}% complete")
        print(f"Downloaded to {output_file}")
    except Exception as e:
        print(f"Error downloading file: {e}")

if __name__ == "__main__":
    file_id = input("Enter Google Drive file ID: ")  # e.g., 1a2b3c4d5e6f7g8h9i0j
    download_from_drive(file_id)
