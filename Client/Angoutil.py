from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.Util.Padding import pad,unpad
from base64 import b64encode, b64decode
from os import makedirs, environ
from os.path import exists, basename
from urllib.parse import quote_from_bytes, unquote_to_bytes

class KeyNotFoundException(Exception):
  def __init__(self, keyname):
    self.keyname = keyname

  def __str__(self):
    return "{} doesn't exist.".format(self.keyname)

class AESCipher():
  def __init__(self, block_size=32):
    self.block_size = block_size
    self.key = None

  def byte2b64(self, byte):
    if not isinstance(byte, bytes):
      raise TypeError("Wrong argument type")
    string  = b64encode(byte).decode('utf-8')
    return string

  def b642byte(self, string):
    if not isinstance(string, str):
      raise TypeError("Wrong argument type")
    byte = b64decode(string.encode('utf-8'))
    return byte

  def hide_name(self, original_name):
    base = basename(original_name)
    return quote_from_bytes(self.encrypt(base.encode()))

  def reveal_name(self, enc_name):
      base = basename(enc_name)
      return self.decrypt(unquote_to_bytes(base)).decode()

  def generate_key(self):
    self.key = Random.get_random_bytes(self.block_size)
    return self.byte2b64(self.key)

  def set_key(self, key):
    if isinstance(key, str):
      self.key = self.b642byte(key)
    elif isinstance(key, bytes):
      self.key = key
    else:
      raise TypeError("Wrong argument type")
    return self.key
  
  def get_key(self):
    return self.b642byte(self.key)

  def get_raw_key(self):
    return self.key

  def encrypt(self, data, output_file = None, hide_name = False):
    cipher = AES.new(self.key, AES.MODE_CBC)
    cipher_data = cipher.iv + cipher.encrypt(pad(data, AES.block_size))

    if output_file != None:
      if hide_name:
        output_file = self.hide_name(output_file)
      with open(output_file, "wb") as f:
        f.write(cipher_data)
    return cipher_data

  def decrypt(self, data, output_file = None):
    iv = data[0:16]
    cipher_data = data[16:]
    decipher = AES.new(self.key, AES.MODE_CBC, iv = iv)
    decipher_data = unpad(decipher.decrypt(cipher_data), AES.block_size)
    
    if output_file != None:
      with open(output_file, "wb") as f:
        f.write(decipher_data)
    return decipher_data

  def encrypt_file(self, file_path, output_file = None, hide_name = False):
    with open(file_path, "rb") as f:
      data = f.read()
    return self.encrypt(data, output_file, hide_name)

  def decrypt_file(self, file_path, output_file = None, reveal_name = False):
    with open(file_path, "rb") as f:
      data = f.read()
    if output_file and reveal_name:
      output_file = self.reveal_name(file_path)
    return self.decrypt(data, output_file)

class RSACipher:
  def __init__(self):
    self.privatekey = None
    self.publickey = None
    self.user = environ.get("USERNAME",'someone')
    self.privatekey_path = ".secret/"+self.user+"_pri_key.pem"
    self.publickey_path = ".secret/"+self.user+"_pub_key.pem"
    makedirs("./.secret",exist_ok = True)

  def generate_keys(self, key_size = 2048):
    random_func = Random.new().read
    self.privatekey = RSA.generate(key_size, random_func)
    with open(self.privatekey_path,"w") as f:
      pri_key = self.privatekey.export_key(format="PEM").decode('utf-8')
      f.write(pri_key)

    self.publickey = self.privatekey.publickey()
    with open(self.publickey_path, "w") as f:
      pub_key  = self.publickey.export_key().decode('utf-8')
      f.write(pub_key)

    return (self.publickey,self.privatekey)

  def read_privatekey(self, privatekey_path = None):
    if not privatekey_path:
      privatekey_path = self.privatekey_path
    if exists(privatekey_path):
      with open(privatekey_path,'rb') as f:
        self.privatekey = RSA.import_key(f.read())
    else:
      raise KeyNotFoundException("Private key")
    return self.privatekey

  def read_publickey(self, publickey_path = None):
    if not publickey_path:
      publickey_path = self.publickey_path
    if exists(publickey_path):
      with open(publickey_path,'rb') as f:
        self.publickey = RSA.import_key(f.read())
    else:
      raise KeyNotFoundException("Public key")
    return self.publickey

  def read_keys(self, publickey_path = None, privatekey_path = None):
    if not publickey_path: publickey_path = self.publickey_path
    if not privatekey_path: privatekey_path = self.privatekey_path
    return (self.read_publickey(publickey_path),self.read_privatekey(privatekey_path))
  
  def encrypt(self, data, output_file = None):
    pub_key = self.publickey
    cipher = PKCS1_OAEP.new(pub_key)
    cipher_data = cipher.encrypt(data.encode('utf-8'))

    if output_file != None:
      with open(output_file, "wb") as f:
        f.write(cipher_data)
    return cipher_data

  def decrypt(self, data, output_file = None):
    pri_key = self.privatekey
    decipher = PKCS1_OAEP.new(pri_key)
    decipher_data = decipher.decrypt(data).decode('utf-8')

    if output_file != None:
      with open(output_file, "w") as f:
        f.write(decipher_data)
    return decipher_data
