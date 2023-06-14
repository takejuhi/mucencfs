## print用
from __future__ import print_function, with_statement
from pprint import pprint
from mimetypes import guess_type

from pickle import load as pickle_load, dump as pickle_dump
import os.path
from io import FileIO
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload,MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import _Response, Request

from traceback import format_exc

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
CONFIG_PATH = "efuse_config.pickle"

class DriveController:
  def __init__(self):
    self.creds, self.service = self.auth()
    self._CONFIG = None
    self.load_config()

  def def_val(self,name,value):
    try:
      exec("self.{}={}".format(name,value))
      return self.__dict__[name]
    except:
      return False

  def setup(self):
    self.creds, self.service = self.auth()
    self.load_config()
    try:
      self._CONFIG["root"]
    except KeyError:
      self.create_root()

  def auth(self):
    creds = None
    if os.path.exists(TOKEN_PATH):
      with open(TOKEN_PATH,'rb') as token:
        try:
          creds = pickle_load(token)
        except Exception as e:
          print(e)
    if not creds or not creds.valid or not creds.has_scopes(SCOPES):# スコープを変更しないようになったら最後の条件消す
      if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
      else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
      with open(TOKEN_PATH, 'wb') as token:
        pickle_dump(creds, token)
    service = build('drive', 'v3', credentials=creds)
    return creds, service

  def create_root(self):
    file_metadata = {'name':"EFUSE",'mimeType': 'application/vnd.google-apps.folder'}
    if not self._CONFIG:self.load_config()
    try:
      file = self.service.files().create(body=file_metadata, fields='id').execute()
      index = self.service.files().create(body={'name':".index.pickle"}).execute()
      self._CONFIG["root"] = file.get('id')
      self.save_config()
      return file.get('id')
    except Exception as e:
      return str(e)
  
  def get_root_id(self):
    try:
      return self._CONFIG["root"]
    except KeyError:
      return Exception("Not Found")

  def load_config(self):
    if os.path.exists(CONFIG_PATH):
      with open(CONFIG_PATH,'rb') as config:
        try:
          self._CONFIG = pickle_load(config)
        except:
          self._CONFIG = {}
          return self.save_config()
        else:
          return True
    else:
      self._CONFIG = {}
      return self.save_config()

  def save_config(self):
    if not self._CONFIG:
      return False
    with open(CONFIG_PATH,'wb+') as config:
      try:
        pickle_dump(self._CONFIG,config)
        return True
      except Exception as e:
        print(e)
        return False

  def refresh(self):
    self.creds.refresh(Request())
    with open(TOKEN_PATH, "wb") as token:
      pickle_dump(self.creds, token)
    self.service = build('drive', 'v3', credentials=self.creds)
    return self.creds,self.service

  def getattr(self, fileID):
    try:
      response = self.service.files().get(fileId = fileID, fields="id,mimeType,name,size,modifiedTime,createdTime,trashed,ownedByMe").execute()
      return response
    except Exception as e:
      print("getattr",e)
      raise FileNotFoundError(2, os.strerror(2),fileID)

  def readdir(self, parent=None):
    if not parent:parent = self._CONFIG["root"]
    page_token = None
    while True:
      response = self.service.files().list(fields="nextPageToken, files(*)",pageSize=20,q="'{}' in parents and trashed = false".format(parent),pageToken=page_token).execute()
      page_token = response.get("nextPageToken",None)
      for file in response.get("files",[]):
        yield file
      if not page_token:
        break

  def searchdir(self, name, parent=None):
    # GDrive謎仕様メモ
    # .(ドット)の前英字4文字だけの検索はできない.結果が0
    # ひらがなだと3文字以下がダメ
    # ドットを含み５文字(ひらがなだと4文字)以上になる場合でも同様
    # ドット以降は3文字でも可
    if not parent:parent = self._CONFIG["root"]
    page_token = None
    while True:
      response = self.service.files().list(fields="nextPageToken, files(*)",pageSize=20,q="'{}' in parents and trashed = false and name contains '{}'".format(parent,name),pageToken=page_token).execute()
      page_token = response.get("nextPageToken",None)
      for file in response.get("files",[]):
        yield file
      if not page_token:
        break

  def readshared(self,parent=None):
      page_token = None
      while True:
        response = self.service.files().list(fields="nextPageToken, files(*)",pageSize=20,q=parent + " in parents and " if parent else "" + "sharedWithMe = true and trashed = false",pageToken=page_token).execute()
        page_token = response.get("nextPageToken",None)
        for file in response.get("files",[]):
          yield file
        if not page_token:
          break
    
  def upload_file(self,path, name, parent=None, fileID=None, mime=None):
    file_metadata = {'name': name}
    if not mime:
      m = guess_type(name)[0]
      mime = "text/plain" if not m else m
    media = MediaFileUpload(path, mimetype=mime, resumable=True) if path else None
    try:
      if fileID:
        file = self.service.files().update(fileId=fileID,body=file_metadata,media_body=media,fields='id').execute()
      else:
        if not parent:parent = self._CONFIG["root"]
        file_metadata['parents'] = [parent]
        file = self.service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    except Exception as e:
      print(e)
      return str(e)
    print("Upload.",path)
    return file.get("id")

  def upload_folder(self, path, name, parent=None, folderID=None):
    file_metadata = {'name': name,'mimeType':'application/vnd.google-apps.folder'}
    try:
      if folderID:
        folder = self.service.files().update(fileId = folderID, body=file_metadata, fields='id').execute()
      else:
        if not parent:parent = self._CONFIG["root"]
        file_metadata['parents'] = [parent]
        folder = self.service.files().create(body=file_metadata, fields='id').execute()
      return folder.get("id")
    except Exception as e:
      print(e)
      return str(e)

  def delete(self, fileID):
    try:
      response = self.service.files().delete(fileId=fileID).execute()
    except Exception as e:
      print(e)
      return e
    return response
  
  def download(self,fileID,fileName):
    request = self.service.files().get_media(fileId = fileID)
    # try:
    fh = FileIO(fileName,mode="wb")
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
      status, done = downloader.next_chunk()
      print("Download %d%%." % int(status.progress() * 100),fileName)

  def share(self,fileID,email,role='writer'):
    batch = self.service.new_batch_http_request(callback=lambda request_id, response, exception: print(exception) if exception else print("Permission Id: {}".format(response.get('id'))))
    user_permission = {
      'type': 'user',
      'role': role,
      'emailAddress': email
      }
    batch.add(self.service.permissions().create(fileId=fileID, body=user_permission, fields='id', sendNotificationEmail = False))
    batch.execute()
  
  def unshare(self, fileID, permissionID):
    try:
      self.service.permissions().delete(fileId=fileID,permissionId=permissionID).execute()
    except Exception as e:
      print(e)
      return False

  def unshareAll(self, fileID):
    permissions = list(self.getshare(fileID))
    for permission in permissions:
      if permission['role'] == "owner":continue
      self.unshare(fileID, permission['id'])

  def getshare(self, fileID):
    try:
      response = self.service.permissions().list(fileId=fileID,fields='permissions(id,emailAddress,type,role,displayName)').execute()
      for permission in response.get("permissions", []):
        yield permission
    except Exception as e:
      return print(e)

  def getpermission(self, fileID, permissionID):
    response = self.service.permissions().get(fileId=fileID,permissionId=permissionID).execute()
    return response

  def getowner(self):
    response = self.service.about().get(fields = "user").execute()
    return response.get('user')

  def getnewID(self):
    response = self.service.files().generateIds(count=1,space="drive").execute()
    return response.get('ids')[0]

  def movetrash(self, ID):
    file_metadata = {'trashed': True}
    try:
      resID = self.service.files().update(fileId = ID, body=file_metadata, fields='id').execute()
      # 過去ver?
      # self.service.files().trash(fileId=ID).execute()
      return resID
    except Exception as e:
      print(e)
      return False
  
  def move(self, ID, oldFolderID, newFolderID):
    self.service.files().update(fileId=ID, removeParents=[oldFolderID],addParents=[newFolderID], fields='id').execute()

def printgenerator(gen):
  for i in gen:
    print(i)

print(__name__,"imported")
if __name__ == '__main__':
  con = DriveController()
##  r1 = con.readdir()
  r2 = con.readshared()
  for l in r2:
    r=l
elif __name__ == 'ClientAPI' and False:
  con=DriveController()
  # Listing
  files = list(con.readdir())
  # download
  # con.download(files[-1]["id"],"example10M")
  # getattr
  res = con.getattr(files[0]['id'])
  # List Shared
  # shared = list(con.readshared())
  # for index,file in enumerate(shared):
  #   print(index,file['id'],file['name'])
  # Upload
  # con.upload_file("TestFiles/test100M","example100M")
  # Upload Folder
  # folder = con.upload_folder(None, "Upload_Test")

  # Sharing
  # for f in files:
  #   print(f["name"],f["mimeType"])
  # ind = int(input("file番号?"))
  # con.share(files[0]["id"],"@gmail.com")
  # printgenerator(con.getshare(files[0]['id']))

  # About
  # res = con.getowner()
  pass
