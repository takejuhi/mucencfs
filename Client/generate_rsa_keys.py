from Angoutil import RSACipher, KeyNotFoundException
from shutil import copy2
from os import getcwd

if __name__ == '__main__':
  rsa = RSACipher()
  try:
    rsa.read_keys()
  except KeyNotFoundException:
    rsa.generate_keys()
    copy2(rsa.publickey_path, getcwd())
