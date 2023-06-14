from __future__ import with_statement

import os,sys,errno

from fuse import FUSE, FuseOSError, Operations

import time, atexit, signal, uuid, traceback
from shutil import rmtree
from threading import Timer
from datetime import datetime
from pickle import NONE, load as pload, dump as pdump, loads as ploads, dumps as pdumps
from io import UnsupportedOperation
from re import sub
from traceback import format_exc

from Angoutil import *
from ClientAPI import DriveController

DEBUG = False # Trueで全ての出力を行う

SERVER_IP = "10.31.19.17" # 適宜変更
SERVER_PORT = 4433

MIME_GOOGLE_FOLDER = 'application/vnd.google-apps.folder'
INDEX_INTERVAL = 15

MOUNTED_DIR = os.path.join(os.getcwd(),".mounted")
MOUNT_DIR = os.path.join(os.environ["HOME"],"MountPoint")
ENCRYPTED_DIR = os.path.join(os.getcwd(),".encrypted")

def get_pathname(owner_id, shared_id):
  from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
  from ssl import SSLContext, PROTOCOL_TLSv1_2
  from Angoutil import RSACipher
  rsa = RSACipher()
  try:
    rsa.read_keys()
  except KeyNotFoundException:
    rsa.generate_keys()

  context = SSLContext(PROTOCOL_TLSv1_2)
  sock = socket(AF_INET, SOCK_STREAM)
  ssock = context.wrap_socket(sock, server_hostname=SERVER_IP)
  ssock.settimeout(20)
  # print(f"{ssock.version()=}")
  message = "pathname,{},{}".format(owner_id, shared_id)
  try:
    ssock.connect((SERVER_IP, SERVER_PORT))
    ssock.send(message.encode())
    response = ssock.recv(1024)
    decrypted_response = rsa.decrypt(response)
  except Exception as e:
    print(format_exc())
    decrypted_response = False
  finally:
    ssock.shutdown(SHUT_RDWR)
    ssock.close()
  return decrypted_response

class Passthrough(Operations):
    """customized FUSE"""
    def __init__(self, root):
      print(time.asctime(),"fuse init")
      self.root = root
      self.ENCRYPTION = True # 暗号化の行うかどうか。path_index導入後Falseの挙動未確認。
      self.ACCURATE = False # path_indexリクエストインターバルを考慮するかどうか。Trueだと毎回リクエストする
      self.CACHE_PATHNAME = True # path_index名を初回リクエスト時に取得したものを利用するかどうか。Falseだとサーバに毎回リクエストする
      self.con = DriveController()
      self.user = self.con.getowner()
      self.user["uname"] = self._user_name(self.user["emailAddress"])
      self._CACHE = {"paths":{}} # path_index, indexのロード時刻保存用
      self._IDs = {} # ファイルIDキャッシュ用
      self._path_data = self._read_path_index(self.user["uname"]) # path_indexデータキャッシュ用
      self._fix_resisterd("/",self.con.get_root_id()) 
      self.cipher = {"aes": AESCipher(),"rsa":RSACipher()}
      try:
          (publickey, privatekey) = self.cipher["rsa"].read_keys()
      except KeyNotFoundException:
          (publickey, privatekey) = self.cipher["rsa"].generate_keys()
      finally: # 何かに使用可能かと考えたが不要
          globals()["publickey"] = publickey
          globals()["prvatekey"] = privatekey
      print("username is ",self.user["uname"])

    def _full_path(self, partial) -> str:
      """MountPointからのパスに変換"""
      if partial.startswith("/"):
          partial = partial[1:]
      path = os.path.join(self.root, partial)
      return path

    def _user_name(self, emailAddress):
        """user id 導出用。Google Driveのためメールアドレスのドメインを除いた部分としている"""
        return sub("^([\w\.\-]*?)@gmail.com","\\1",emailAddress)

    def _make_meta(self, path_dict):
        """Google DriveからのresponseとFUSEで必要なメタデータの型の差分埋め"""
        if type(path_dict) != dict:
            print("API getattr",path_dict)
            return {}
        mime = path_dict.get("mimeType")
        if mime == MIME_GOOGLE_FOLDER:
            mode = 16893
            links = path_dict.get('links',2)
        else:
            mode = 33204
            links = 1
        # GDriveからはisoformat
        # GDriveからresponse得るたびにisoをtimestampに変換する
        try:
            ctime = datetime.fromisoformat(path_dict.get("createdTime").__str__().replace("Z","+00:00")).timestamp()
            mtime = datetime.fromisoformat(path_dict.get("modifiedTime").__str__().replace("Z","+00:00")).timestamp()
        except (TypeError, ValueError):
            ctime = path_dict.get("createdTime")
            mtime = path_dict.get("modifiedTime")
        if not ctime or not mtime:
            print(path_dict)
            ctime = mtime = atime = datetime.now().timestamp()
            links = 2
            mode = 16893
        meta = {'st_atime':mtime,'st_ctime':ctime,'st_mtime':mtime,'st_mode':mode,'st_gid':os.getgid(),'st_uid':os.getuid(),'st_size':int(path_dict.get("size",4096)),'st_nlink':links}
        return meta

    def _fix_resisterd(self,path, folder_id):
        if self._path_data.get(path):
            return True
        else:
            try:
                print("fix path_index")
                response = self.con.getattr(folder_id)
                meta = self._make_meta(response)
                self._push_path_index(path, {'id':folder_id,'index':{},'meta':{'createdTime':meta["st_ctime"],'modifiedTime':meta["st_mtime"],'links':2, 'mimeType': MIME_GOOGLE_FOLDER}})
            except NameError as e:
                print("NameError",e.__str__())
            except Exception as e:
                print(format_exc())
            finally:
                return False

    def _read_path_index(self, uname = None):
        # self._path_data = dataを呼び出し元でやる
        print("_read_path_index:")
        con = DriveController()
        if not uname:uname = self.user["uname"]# 所有者自身
        if not self._CACHE['paths'].get(uname, {}).get('pathname') or not self.CACHE_PATHNAME:
            try:
                pathname = "." + get_pathname(uname,uname) + ".path"
            except TypeError:
                pathname = self._CACHE['paths'][uname]['pathname']
        else:pathname = self._CACHE['paths'][uname]['pathname']
        # ローカルのパス
        rootIndexPath = os.path.join(self.root, pathname)
        if not self._CACHE['paths'].get(uname):
            rootIndex = list(con.searchdir(pathname))
            if not len(rootIndex): # path_index初期化
                print(f"*** {uname}'s path_index not found *** ")
                with open(rootIndexPath,"wb")as f:
                  pdump({},f)
                self._CACHE['paths'][uname] = {'id':con.upload_file(rootIndexPath, pathname),'pathname':pathname,'loaded':datetime.now().timestamp()}
            else: # path_index発見時
                print("path_index found")
                self._CACHE['paths'][uname] = {'id':rootIndex[0]["id"],'pathname':pathname,'loaded':datetime.fromisoformat(rootIndex[0]["modifiedTime"].__str__().replace("Z","+00:00")).timestamp()}
                con.download(rootIndex[0]["id"],rootIndexPath)
                print(time.asctime(),"download path_index")
            print(f"{self._CACHE['paths']=}")
        elif not self.ACCURATE and not datetime.now().timestamp() - self._CACHE["paths"][uname].get("loaded", 0) < INDEX_INTERVAL: # 更新時刻確認
            mtime = datetime.fromisoformat(con.getattr(self._CACHE['paths'][uname].get('id'))["modifiedTime"].__str__().replace("Z","+00:00")).timestamp()
            if not 0 <= mtime - float(self._CACHE['paths'][uname].get('mtime',0)) < 0.5:
                try:
                    print(time.asctime(),"load root index")
                    con.download(self._CACHE['paths'][uname].get('id'),rootIndexPath)
                except Exception as e: # 取得に失敗(==存在しない)
                    # 削除して作り直し
                    print(format_exc())
                    os.unlink(rootIndexPath)
                    self._CACHE['paths'].pop(uname)
                    return self._read_path_index(uname)
            self._CACHE['paths'][uname].update({'mtime':mtime, 'loaded':datetime.now().timestamp()})
        with open(rootIndexPath,"rb") as f:
            try:
                data = pload(f)
            except (UnsupportedOperation, EOFError):
                print(format_exc())
                data = {}
        return data

    def _push_path_index(self, path, newdata = None):
        # path:共有中ユーザID取得のため
        con = DriveController()
        try:
            permissions = list(con.getshare(self._path_data[path]['id']))
        except (KeyError):
            permissions = [self.user]
        pathindexs = list(con.searchdir(".pickle"))
        print(time.asctime(),"push path_index:",len(permissions),"users.")
        for permission in permissions:
            uname = self._user_name(permission.get("emailAddress"))
            if not self._CACHE['paths'].get(uname, {}).get('pathname') or not self.CACHE_PATHNAME:
                try:
                    pathname = "." + get_pathname(uname,uname) + ".path"
                except TypeError:# 一時的な処理
                    pathname = self._CACHE['paths'][uname]['pathname']
            else:pathname = self._CACHE['paths'][uname]['pathname']
            # ローカルのパス
            rootIndexPath = os.path.join(self.root, pathname)
            path_data = self._read_path_index(uname)
            if newdata is not None:
              path_data[path] = newdata
            else:
                path_data.pop(path)
            with open(rootIndexPath,"wb")as f:
                try:
                    pdump(path_data,f)
                except Exception as e:
                    print(format_exc())
            self._path_data = path_data
            # thread化
            for path_file in pathindexs:
                if path_file["name"] == pathname:
                    self._CACHE['paths'][uname] = {'id':path_file["id"]}
                    break
            print(uname,os.path.getsize(rootIndexPath))
            response = con.upload_file(rootIndexPath,pathname,parent=con.get_root_id(),fileID=self._CACHE["paths"][uname]["id"])

    def _read_index(self,path, uname = None):
        print(time.asctime(),"read index")
        con = DriveController()
        full_path = self._full_path(path)
        if not uname:uname = self.user["uname"]
        # print(full_path,path_data[path].get("index"))
        parent_path = os.path.dirname(self._full_path(path))
        indexpath = os.path.join(parent_path,".{}.index".format(self.user["uname"]))
        path_data = self._read_path_index(uname)
        try:path_data[path]
        except Exception:
            print(format_exc())
            input()
        if not path_data[path].get('index'):
            # クラウドを直接いじったか何かで
            # indexファイルが作成されていない or path_indexに入っていない場合
            indexFile = list(con.searchdir(".index.pickle",path_data[path]['id'])) # このネーミングだと複数ユーザに対応できない→上記の場合はデータが消えた扱いにすべき
            if not len(indexFile):
                print("index not Found",full_path)
                with open(indexpath,"wb") as f:pdump({},f)
                path_data[path]['index'] = {'id':con.upload_file(indexpath, ".index.pickle",parent=path_data[path]['id'])}
                self._CACHE[path] = {'loaded':datetime.now().timestamp()}
            else:
                print("index Found",full_path)
                con.download(indexFile[0]["id"],indexpath)
                path_data[path]['index'] = {'id':indexFile[0]['id']}
                self._CACHE[path] = {'mtime':datetime.fromisoformat(indexFile[0]["modifiedTime"].__str__().replace("Z","+00:00")).timestamp(), 'loaded':datetime.now().timestamp()}
            self._push_path_index(path, path_data[path])
        elif not self.ACCURATE and not datetime.now().timestamp() - self._CACHE.get(path,{}).get("loaded",0) < INDEX_INTERVAL:
            # indexが消えている場合にはここでエラー
            try:
                indexmeta = con.getattr(path_data[path]['index']['id'])
                mtime = datetime.fromisoformat(indexmeta["modifiedTime"].__str__().replace("Z","+00:00")).timestamp()
            except (TypeError, FileNotFoundError):
                path_data[path].pop("index")
                return self._read_index(path, uname)
            if not 0 <= mtime - self._CACHE.get(path,{}).get("mtime",0) < 0.5:
              print("index_download")
              con.download(path_data[path]['index']['id'],indexpath)
              self._CACHE[path] = {'mtime':mtime, 'loaded':datetime.now().timestamp()}
        with open(indexpath, 'rb') as f:
            try:
              data = pload(f)
            except (UnsupportedOperation,EOFError) as e:
              print(format_exc())
              data = {}
        return data
    
    def _push_index(self, path, data):
        print("_push_index",data)
        # thread化？
        con = DriveController()
        parent_path = os.path.dirname(self._full_path(path))
        indexPath = os.path.join(parent_path,".{}.index".format(self.user["uname"]))
        try:
            permissions = list(con.getshare(self._IDs[path]['id']))
        except (KeyError):
            permissions = [self.user]
        for permission in permissions:
            uname = self._user_name(permission.get("emailAddress"))
            indexID = self._path_data[os.path.dirname(path)].get("index", {}).get("id")
        if not indexID:print("INDEX NOT FOUND")
        with open(indexPath, "wb") as f:
            try:
                pdump(data,f)
            except Exception as e:
                print(format_exc())
        con.upload_file(indexPath, ".index.pickle",parent=self._path_data[os.path.dirname(path)]['id'],fileID=indexID)

    def _check_index(self, path, fileID):
        """file_index完全性確認"""
        data = self._read_index(os.path.dirname(path))
        flag = False
        for element in data.get(fileID,[]):
            if not element.get("name"):
                element['name'] = os.path.basename(path)
                flag = True
        if flag:
            self._push_index(path, data)

    def _upload(self, path):
        full_path = self._full_path(path)
        print(time.asctime(), "upload",full_path)
        con = DriveController()
        parent = os.path.dirname(path)
        try: 
            parent_id = self._path_data[parent]["id"]
        except KeyError:
            raise FileNotFoundError(errno.ENOENT,os.strerror(errno.ENOENT),parent)
        if not self.ENCRYPTION:
            file_id = self._IDs[path].get("id") if self._IDs.get(path) else None
            file_id = con.upload_file(full_path,name=os.path.basename(path),parent=parent_id,fileID=file_id)
            self._IDs[path] = {'id':file_id}
            end_time = time.perf_counter_ns()
            print("uploaded:",end_time)
            return True
        # {fileid:[{userid,keyid},{},...],fileid:[{}],..}
        key_path = os.path.join(self._full_path(parent),".key_{}".format(os.path.basename(path)))
        new_path = os.path.join(ENCRYPTED_DIR,".enc_{}".format(os.path.basename(path)))
        data = self._read_index(parent)
        file_data = self._IDs.get(path, {})
        if not data.get(file_data.get("id")):
            # encrypt with new key
            key = self.cipher["aes"].generate_key()
            self.cipher["rsa"].encrypt(key, key_path)
            self.cipher["aes"].encrypt_file(full_path, new_path)
            try:
                keyid = con.upload_file(key_path,os.path.basename(key_path),parent=parent_id)
                file_id = con.upload_file(new_path,os.path.basename(path),parent=parent_id)
                self._IDs[path] = {'id':file_id}
            except Exception as e:
                print(format_exc())
                raise Exception(errno.ECOMM, os.strerror(errno.ECOMM), full_path)
            data[file_id] = [{'userid':self.user.get("emailAddress"),'keyid':keyid,'name':os.path.basename(path)}]
            self._push_index(path, data)
        else:
            # encrypt with current key
            for user_key in data.get(file_data["id"]):
                __builtins__.print(key_path)
                con.download(user_key.get('keyid'),key_path)
                with open(key_path,"rb") as f:
                    key = self.cipher["rsa"].decrypt(f.read())
                    self.cipher["aes"].set_key(key)
                self.cipher["aes"].encrypt_file(full_path, new_path)
                keyid = con.upload_file(key_path,os.path.basename(key_path),parent=self._path_data[parent]['id'],fileID=user_key.get('keyid'))
                con.upload_file(new_path,os.path.basename(path),parent=self._path_data[parent]['id'],fileID=self._IDs[path].get("id"))
            self._IDs[path].pop("timer",None)
        os.unlink(new_path)
        os.unlink(key_path)
        end_time = time.perf_counter_ns()
        print("uploaded:",end_time)
        return

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        print(time.asctime(),"getattr:",full_path,end=' ')
        if self._path_data.get(path):
            # フォルダの場合
            print("FOLDER")
            full_path = full_path[:-1]
            if full_path == MOUNTED_DIR:
                self._path_data = self._read_path_index()
            try:
                meta  = self._make_meta(self._path_data[path]['meta'])
            except KeyError as e:
                print(format_exc())
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
            except Exception as e:
                print(format_exc())
        else:
            # ファイルの場合
            print("FILE")
            index_data = self._read_index(os.path.dirname(path))
            for k,v in index_data.items():
                # フォルダ内のpath名データ
                if v[0].get('name') == os.path.basename(path):
                    fileID = k
                    break
            try:
                response = self.con.getattr(fileID)
                if response.get("trashed"):
                  print(response)
                  index_data.pop(fileID)
                  self._push_index(path, index_data)
                  raise NameError
                if not self._IDs.get(path):
                  self._IDs[path] = {"id": response["id"]}
                meta = self._make_meta(response)
            except (NameError, UnboundLocalError) as e:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
            except Exception as e:
                print(format_exc())
        return meta

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        if full_path.endswith("/"):
            full_path = full_path[:-1]
        print(time.asctime(),"readdir:",full_path,fh)
        try:
            dir_id = self._path_data[path]['id']
        except KeyError:
            list(self.readdir(os.path.dirname(path),fh))
            dir_id = self._path_data[path]['id']
        finally:
            files = list(self.con.readdir(parent=dir_id))
        files.extend([{'name':"."}, {'name':".."}])
        links = len([f for f in files if not f["name"].startswith(".key_") or f["name"].endswith(".index.pickle")])
        index_data = self._read_index(path)
        if self._path_data[path]["meta"]["links"] != links:
            self._path_data[path]["meta"]['links'] = links
            self._push_path_index(path, self._path_data[path])
        for r in files:
            if r["name"].startswith(".key_") or r["name"] in [".", ".."] or r["name"] == ".index.pickle" or r["name"].endswith("path.pickle"):
                continue
            if r.get('mimeType') == MIME_GOOGLE_FOLDER:
                self._fix_resisterd(os.path.join(path,r["name"]),r["id"])
                os.makedirs(os.path.join(full_path,r['name']),exist_ok=True)
            elif not os.path.exists(os.path.join(full_path, r["name"])):
              # indexに保存されていないか消されたかは除外
              if not index_data.get(r["id"]):continue
              print(r["name"],index_data.get(r["id"]))
              try:
                open(os.path.join(full_path,r['name']),mode="a").close()
              except Exception as e:
                print(format_exc())
            yield r['name']

    def rmdir(self, path):
        full_path = self._full_path(path)
        print(time.asctime(),"rmdir",full_path)
        # ID指定
        try:
            folder_id = self._path_data[path]['id']
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),path)
        self.con.movetrash(folder_id)
        self._path_data.pop(path)
        self._push_path_index(path)
        return rmtree(full_path)

    def mkdir(self, path, mode):
        print(time.asctime(),"mkdir:",path,mode)
        full_path = self._full_path(path)
        (parent,name) = os.path.split(path)
        data = self._read_path_index()
        try:
            parent_id = data[parent]['id']
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        try:
            data[path]
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST),path)
        except KeyError:
            now = datetime.now().timestamp()
            folder_id = self.con.upload_folder("", name, parent=parent_id)
            os.makedirs(full_path,exist_ok=True)
            with open(os.path.join(full_path,".index.pickle"), "wb") as f:
                pdump({},f)
            index_id = self.con.upload_file(os.path.join(full_path,".index.pickle"),".index.pickle",parent=parent_id)
            self._push_path_index(path,{'id':folder_id,'meta':{'modifiedTime':now,'createdTime':now,'links':2, 'mimeType':MIME_GOOGLE_FOLDER},'index':{'id':index_id}})
        return None

    def unlink(self, path):
        full_path = self._full_path(path)
        print(time.asctime(),"unlink:",full_path)
        try:
            file_id = self._IDs[path]["id"]
            index_data = self._read_index(os.path.dirname(path))
            keys = index_data.pop(file_id)
        except KeyError:
          print(format_exc())
          raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        self.con.movetrash(file_id)
        for user_key in keys:
            self.con.movetrash(user_key["keyid"])
        self._IDs.pop(path)
        # indexにも反映 or index閲覧時にないファイルを削除？
        self._push_index(path, index_data)
        try:
          result = os.unlink(full_path)
        except FileNotFoundError:
          result = None
        finally:
            return result

    def rename(self, old, new):
        full_path = self._full_path(old)
        print(time.asctime(),"rename",full_path,new)
        basename = os.path.basename(new)
        try:
            if os.path.isdir(full_path):
                if self._path_data.get(new):
                    raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), new)
                folder_id = self._path_data[old]["id"]
                self._path_data[new] = self._path_data.pop(old)
                self.con.upload_folder("", basename,folderID=folder_id)
                self._push_path_index(new)
                self._push_path_index(old)
            else:
                if self._IDs.get(new):
                    raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), new)
                file_id = self._IDs[old]["id"]
                new_index = self._read_index(os.path.dirname(new))
                old_index = self._read_index(os.path.dirname(old))
                if new_index.get(file_id) is not None:
                    raise KeyError
                new_index[file_id] = old_index.get(file_id)
                self._push_index(os.path.dirname(new), new_index)
                self._push_index(os.path.dirname(old), old_index)
                self.con.upload_file("", basename,fileID=file_id)
                self._IDs[new] = self._IDs.pop(old)
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), old)
        return None

    # def link(self, target, name):
    #     print(time.asctime(),"link")
    #     return os.link(self._full_path(target), self._full_path(name))

    # def utimens(self, path, times=None):
    #     full_path = self._full_path(path)
    #     print(time.asctime(),"utimens:",full_path)
    #     # atime,mtime
    #     # raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
    #     return os.utime(full_path, times)

    # def symlink(self, name, target):
    #     print(time.asctime(),"symlink")
    #     return os.symlink(name, self._full_path(target))

    # def readlink(self, path):
    #     print(time.asctime(),"readlink")
    #     pathname = os.readlink(self._full_path(path))
    #     if pathname.startswith("/"):
    #         # Path name is absolute, sanitize it.
    #         return os.path.relpath(pathname, self.root)
    #     else:
    #         return pathname

    def chmod(self, path, mode):
        print(time.asctime(),"chmod")
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    # File methods
    # ============

    def open(self, path, flags):
        # ドライブからDL
        full_path = self._full_path(path)
        print(time.asctime(),"open",full_path,flags)
        try:
            file_id = self._IDs[path]['id']
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),os.path.basename(path))
        if not self.ENCRYPTION:
            self.con.download(file_id, full_path)
            num = os.open(full_path, flags)
            return num
        con = DriveController()
        data = self._read_index(os.path.dirname(path))
        keys = data.get(file_id)
        key_path = os.path.join(ENCRYPTED_DIR,"key_{}".format(os.path.basename(path)))
        new_path = os.path.join(ENCRYPTED_DIR,"enc_{}".format(os.path.basename(path)))
        if not keys:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        for user_key in keys:
            if user_key.get("userid") != self.user.get('emailAddress'):continue
            con.download(user_key.get('keyid'),key_path)
            con.download(file_id, new_path)
            with open(key_path,'rb') as f:
                key = self.cipher["rsa"].decrypt(f.read())
            self.cipher["aes"].set_key(key)
            self.cipher["aes"].decrypt_file(new_path, full_path)
        os.unlink(new_path)
        os.unlink(key_path)
        num = os.open(full_path, flags)
        return num

    def create(self, path, mode, fi=None):
        # ドライブへ作成要求
        full_path = self._full_path(path)
        print(time.asctime(),"create:",full_path)
        if self._IDs.get(path):
            print("EEXIST",self._IDs.get(path))
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)
        parent = os.path.dirname(path)
        try:
          parent_id = self._path_data[parent]['id']
        except KeyError:
          raise FileNotFoundError(errno.ENOENT,os.strerror(errno.ENOENT),parent)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        num = os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        # 以下_uploadで
        self._upload(path)
        time.sleep(5)
        return num

    def read(self, path, length, offset, fh):
        # DLしたファイルを指定
        full_path = self._full_path(path)
        print(time.asctime(),"read",full_path)
        os.lseek(fh, offset, os.SEEK_SET)
        return os.read(fh, length)

    def write(self, path, buf, offset, fh):
        full_path = self._full_path(path)
        # print(time.asctime(),"write",full_path)
        if self._IDs[path].get("timer"):
          self._IDs[path].get("timer").cancel()
        else:
          print(time.asctime(),"write",full_path)
        os.lseek(fh, offset, os.SEEK_SET)
        num = os.write(fh, buf)
        self._IDs[path]["timer"] = Timer(5, self._upload, args = (path,))
        self._IDs[path]["timer"].start()
        return num

    def truncate(self, path, length, fh=None):
        print(time.asctime(),"truncate")
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    # def flush(self, path, fh):
    #     print(time.asctime(),"flush")
    #     return os.fsync(fh)

    def release(self, path, fh):
        full_path = self._full_path(path)
        print(time.asctime(),"release",full_path,fh)
        try:
            self._IDs[path].pop("keyFile")
        except KeyError:
            pass
        return os.close(fh)

    # def fsync(self, path, fdatasync, fh):
    #     print(time.asctime(),"fsync")
    #     return self.flush(path, fh)

def print(*args, **argv):
    if DEBUG:
        __builtins__.print(*args,**argv)

def log(filepath, content):
  if DEBUG:
    return False
  # Log保存用フォルダを事前作成
  with open(os.path.join("Logging",filepath.replace("/","-")),"a") as f:
    __builtins__.print(content, file=f)

def setup():
    os.makedirs(MOUNT_DIR,exist_ok = True)
    os.makedirs(MOUNTED_DIR,exist_ok = True)
    os.makedirs(ENCRYPTED_DIR,exist_ok=True)
    os.chmod(MOUNTED_DIR, 0o777)
    __builtins__.print("!!Set Up!!")

def cleanup():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    rmtree(MOUNT_DIR)
    rmtree(MOUNTED_DIR)
    rmtree(ENCRYPTED_DIR)
    __builtins__.print("!!Clean Up!!")
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

def sig_handler(signum, frame):
    sys.exit(1)

def main(operations,mountpoint):
    FUSE(operations, mountpoint, nothreads=True, foreground=True, default_permissions=True)

if __name__ == '__main__':
    setup()
    signal.signal(signal.SIGTERM, sig_handler)
    atexit.register(cleanup)
    myfuse = Passthrough(MOUNTED_DIR)
    main(myfuse,MOUNT_DIR)