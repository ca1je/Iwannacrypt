import base64
import hashlib
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from gmssl import sm2, sm3, sm4
import binascii
import urllib.parse
import argparse

class EncryptDecryptTool:
    def __init__(self):
        pass

    # Base64 编码
    def base64_encode(self, data):
        return base64.b64encode(data.encode()).decode()

    # Base64 解码
    def base64_decode(self, data):
        return base64.b64decode(data).decode()

    # Hex 编码
    def hex_encode(self, data):
        return binascii.hexlify(data.encode()).decode()

    # Hex 解码
    def hex_decode(self, data):
        return binascii.unhexlify(data).decode()

    # URL 编码
    def url_encode(self, data):
        return urllib.parse.quote(data)

    # URL 解码
    def url_decode(self, data):
        return urllib.parse.unquote(data)

    # Unicode 编码
    def unicode_encode(self, data):
        return data.encode("unicode_escape").decode()

    # Unicode 解码
    def unicode_decode(self, data):
        return data.encode().decode("unicode_escape")

    # MD5 哈希
    def md5_hash(self, data):
        return hashlib.md5(data.encode()).hexdigest()

    # SHA256 哈希
    def sha256_hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    # SM3 哈希
    def sm3_hash(self, data):
        return sm3.sm3_hash(data.encode())

    # AES 加密
    def aes_encrypt(self, data, key, iv):
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode()

    # AES 解密
    def aes_decrypt(self, encrypted_data, key, iv):
        encrypted_data = base64.b64decode(encrypted_data)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, AES.block_size).decode()

    # DES 加密
    def des_encrypt(self, data, key):
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        padded_data = pad(data.encode(), DES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode()

    # DES 解密
    def des_decrypt(self, encrypted_data, key):
        encrypted_data = base64.b64decode(encrypted_data)
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, DES.block_size).decode()

    # RSA 生成密钥对
    def rsa_generate_keys(self, key_size=2048):
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode(), public_key.decode()

    # RSA 加密
    def rsa_encrypt(self, data, public_key):
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_data = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()

    # RSA 解密
    def rsa_decrypt(self, encrypted_data, private_key):
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_data = base64.b64decode(encrypted_data)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode()

    # SM2 生成密钥对
    def sm2_generate_keys(self):
        private_key = sm2.gen_private_key()
        public_key = sm2.gen_public_key(private_key)
        return private_key, public_key

    # SM2 加密
    def sm2_encrypt(self, data, public_key):
        sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=None)
        encrypted_data = sm2_crypt.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()

    # SM2 解密
    def sm2_decrypt(self, encrypted_data, private_key):
        sm2_crypt = sm2.CryptSM2(public_key=None, private_key=private_key)
        encrypted_data = base64.b64decode(encrypted_data)
        decrypted_data = sm2_crypt.decrypt(encrypted_data)
        return decrypted_data.decode()

    # SM4 加密
    def sm4_encrypt(self, data, key):
        sm4_crypt = sm4.CryptSM4()
        sm4_crypt.set_key(key.encode(), sm4.SM4_ENCRYPT)
        encrypted_data = sm4_crypt.crypt_ecb(data.encode())
        return base64.b64encode(encrypted_data).decode()

    # SM4 解密
    def sm4_decrypt(self, encrypted_data, key):
        sm4_crypt = sm4.CryptSM4()
        sm4_crypt.set_key(key.encode(), sm4.SM4_DECRYPT)
        encrypted_data = base64.b64decode(encrypted_data)
        decrypted_data = sm4_crypt.crypt_ecb(encrypted_data)
        return decrypted_data.decode()


def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt data using various algorithms.")
    parser.add_argument("algorithm", choices=["base64", "hex", "url", "unicode", "md5", "sha256", "sm3", "aes", "des", "rsa", "sm2", "sm4"],
                        help="Algorithm to use for encryption/decryption")
    parser.add_argument("mode", choices=["encode", "decode", "encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("data", help="Data to encode/decode/encrypt/decrypt")
    parser.add_argument("--key", help="Key for encryption/decryption (required for AES, DES, SM4)")
    parser.add_argument("--iv", help="Initialization vector for AES (required for AES)")
    parser.add_argument("--public_key", help="Public key for RSA/SM2 encryption")
    parser.add_argument("--private_key", help="Private key for RSA/SM2 decryption")

    args = parser.parse_args()

    tool = EncryptDecryptTool()

    if args.algorithm in ["base64", "hex", "url", "unicode"]:
        if args.mode == "encode":
            if args.algorithm == "base64":
                result = tool.base64_encode(args.data)
            elif args.algorithm == "hex":
                result = tool.hex_encode(args.data)
            elif args.algorithm == "url":
                result = tool.url_encode(args.data)
            elif args.algorithm == "unicode":
                result = tool.unicode_encode(args.data)
        elif args.mode == "decode":
            if args.algorithm == "base64":
                result = tool.base64_decode(args.data)
            elif args.algorithm == "hex":
                result = tool.hex_decode(args.data)
            elif args.algorithm == "url":
                result = tool.url_decode(args.data)
            elif args.algorithm == "unicode":
                result = tool.unicode_decode(args.data)
        else:
            raise ValueError("Invalid mode for encoding/decoding")
    elif args.algorithm in ["md5", "sha256", "sm3"]:
        if args.mode != "hash":
            raise ValueError("Hash algorithms only support 'hash' mode")
        if args.algorithm == "md5":
            result = tool.md5_hash(args.data)
        elif args.algorithm == "sha256":
            result = tool.sha256_hash(args.data)
        elif args.algorithm == "sm3":
            result = tool.sm3_hash(args.data)
    elif args.algorithm == "aes":
        if not args.key or not args.iv:
            raise ValueError("AES encryption/decryption requires --key and --iv")
        if args.mode == "encrypt":
            result = tool.aes_encrypt(args.data, args.key, args.iv)
        elif args.mode == "decrypt":
            result = tool.aes_decrypt(args.data, args.key, args.iv)
    elif args.algorithm == "des":
        if not args.key:
            raise ValueError("DES encryption/decryption requires --key")
        if args.mode == "encrypt":
            result = tool.des_encrypt(args.data, args.key)
        elif args.mode == "decrypt":
            result = tool.des_decrypt(args.data, args.key)
    elif args.algorithm == "rsa":
        if args.mode == "encrypt":
            if not args.public_key:
                raise ValueError("RSA encryption requires --public_key")
            result = tool.rsa_encrypt(args.data, args.public_key)
        elif args.mode == "decrypt":
            if not args.private_key:
                raise ValueError("RSA decryption requires --private_key")
            result = tool.rsa_decrypt(args.data, args.private_key)
    elif args.algorithm == "sm2":
        if args.mode == "encrypt":
            if not args.public_key:
                raise ValueError("SM2 encryption requires --public_key")
            result = tool.sm2_encrypt(args.data, args.public_key)
        elif args.mode == "decrypt":
            if not args.private_key:
                raise ValueError("SM2 decryption requires --private_key")
            result = tool.sm2_decrypt(args.data, args.private_key)
    elif args.algorithm == "sm4":
        if not args.key:
            raise ValueError("SM4 encryption/decryption requires --key")
        if args.mode == "encrypt":
            result = tool.sm4_encrypt(args.data, args.key)
        elif args.mode == "decrypt":
            result = tool.sm4_decrypt(args.data, args.key)

    print("Result:", result)


if __name__ == "__main__":
    main()