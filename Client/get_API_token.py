from __future__ import print_function, with_statement
from traceback import format_exc

from pickle import load as pickle_load, dump as pickle_dump
from os.path import exists
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

SCOPES = [
    'https://www.googleapis.com/auth/drive',
##    "https://www.googleapis.com/auth/drive.readonly",
##    "https://www.googleapis.com/auth/drive.appdata",
##    "https://www.googleapis.com/auth/drive.file",
##    "https://www.googleapis.com/auth/drive.install",
##    "https://www.googleapis.com/auth/drive.apps.readonly",
##    "https://www.googleapis.com/auth/drive.metadata",
##    "https://www.googleapis.com/auth/drive.metadata.readonly",
##    "https://www.googleapis.com/auth/drive.activity",
##    "https://www.googleapis.com/auth/drive.activity.readonly",
##    "https://www.googleapis.com/auth/drive.scripts"
    ]
TOKEN_PATH = "token.pickle"
class DriveController:
  def __init__(self):
    self.creds = self.setup()

  def setup(self):
    creds = None
    if exists(TOKEN_PATH):
      with open(TOKEN_PATH,'rb') as token:
        try:
          creds = pickle_load(token)
        except:
          pass
    if not creds or not creds.valid or not creds.has_scopes(SCOPES):# スコープを変更しないようになったら消す
      if creds and creds.expired and creds.refresh_token:
        try:
          creds.refresh(Request())
          print("refreshed")
        except RefreshError as e:
          print(format_exc())
          from os import unlink
          unlink(TOKEN_PATH)
          return self.setup()
      else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
      with open(TOKEN_PATH, 'wb') as token:
        pickle_dump(creds, token)
    return creds

  
if __name__ == '__main__':
  con = DriveController()