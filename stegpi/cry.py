import gzip
import hashlib
import sys
import re
import subprocess
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes

sys.dont_write_bytecode = True


class Crypt:
    def __init__(self, message_or_cipher:str|bytes, password:str|bytes) -> None:
        self.__message_or_cipher = message_or_cipher if type(message_or_cipher) == bytes else message_or_cipher.encode()
        self.__password = password if type(password) == bytes else password.encode()
        self.__cipher_config = {
            'IV_LENGTH': 16,
            'SALT_LENGTH': 64,
            'KEY_LENGTH': 32,
            'HASH_NAME': 'SHA512',
            'TAG_LENGTH': 16,
            'iterations': 210000
        }

    def __compress_message(self):
        self.__message_or_cipher = gzip.compress(self.__message_or_cipher)
        
    def __decompress_message(self):
        self.__message_or_cipher = gzip.decompress(self.__message_or_cipher)

    def gpg_encrypt_message(self):
        if type(self.__message_or_cipher) == bytes: self.__message_or_cipher = self.__message_or_cipher.decode()
        spchars = set(re.findall(r"[^A-Za-z0-9\\]", self.__message_or_cipher))
        for spchar in spchars: self.__message_or_cipher = self.__message_or_cipher.replace(spchar, fr'\{spchar}')
        return subprocess.check_output(f"echo -e {self.__message_or_cipher} |\
                                gpg --batch --passphrase-fd 3 --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo sha512 --cipher-algo AES256 --symmetric --armor 3<<<'{self.__password}'", 
                                shell=True)

    def gpg_decrypt_message(self):
        if type(self.__message_or_cipher) == bytes: self.__message_or_cipher = self.__message_or_cipher.decode()
        return subprocess.check_output([f'echo -e "{self.__message_or_cipher}" | gpg --batch -q --passphrase-fd 3 --decrypt 3<<<{self.__password}'], shell=True) 

    def gcm_encrypt_message(self):
        IV_LENGTH = self.__cipher_config['IV_LENGTH']
        SALT_LENGTH = self.__cipher_config['SALT_LENGTH']
        KEY_LENGTH = self.__cipher_config['KEY_LENGTH']
        HASH_NAME = self.__cipher_config['HASH_NAME']
        iterations = self.__cipher_config['iterations']
        
        self.__compress_message()
        iv = get_random_bytes(IV_LENGTH)
        salt = get_random_bytes(SALT_LENGTH)
        secret_key = hashlib.pbkdf2_hmac(HASH_NAME, self.__password, salt, iterations, KEY_LENGTH)
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)

        encrypted_message_byte, tag = cipher.encrypt_and_digest(self.__message_or_cipher)
        self.__message_or_cipher = iv + salt + encrypted_message_byte + tag
        return iv + salt + encrypted_message_byte + tag

    def gcm_decrypt_message(self):
        IV_LENGTH = self.__cipher_config['IV_LENGTH']
        SALT_LENGTH = self.__cipher_config['SALT_LENGTH']
        KEY_LENGTH = self.__cipher_config['KEY_LENGTH']
        TAG_LENGTH = self.__cipher_config['TAG_LENGTH']
        HASH_NAME = self.__cipher_config['HASH_NAME']
        iterations = self.__cipher_config['iterations']

        iv_start, iv_end = (0, IV_LENGTH)
        salt_start, salt_end = (iv_end, iv_end + SALT_LENGTH)
        cipher_start, cipher_end = (salt_end, len(self.__message_or_cipher)-TAG_LENGTH)
        tag_start = cipher_end

        iv = self.__message_or_cipher[iv_start:iv_end]
        salt = self.__message_or_cipher[salt_start:salt_end]
        cipher = self.__message_or_cipher[cipher_start:cipher_end]
        tag = self.__message_or_cipher[tag_start:]

        secret_key = hashlib.pbkdf2_hmac(HASH_NAME, self.__password, salt, iterations, KEY_LENGTH)
        decipher = AES.new(secret_key, AES.MODE_GCM, iv)

        try:
            msg = decipher.decrypt_and_verify(cipher, tag)
            self.__message_or_cipher = msg
            self.__decompress_message()
            return self.__message_or_cipher
        except:
            return
        
if __name__ == '__main__':
    crypt = Crypt('test', 'kkk')
    cipher = crypt.gcm_encrypt_message()

    decrypt = Crypt(cipher, 'kkk6')
    msg = decrypt.gcm_decrypt_message()

    print(cipher)
    print(msg)