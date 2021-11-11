import os
import base64
import json
import socket
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512, SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


def error_page(message):
    return f'''
    <html>
    <head>
        <body>
            <h1>ERROR</h1>
            </br>
            <h1>{message}</h1>
        </body>
    </html>
    '''


def static_page(path):
    return open('static/' + path, 'r').read()


def random_name():
    return base64.urlsafe_b64encode(os.urandom(15)).decode('utf8')


def hash_password(password):
    return SHA512.new(data=password).digest()


def generate_rsa_keys(secret_key=None):
    key = RSA.generate(2048)
    private_key = key.export_key(format="DER", passphrase=secret_key, pkcs=8)
    public_key = key.publickey().export_key(format="DER")

    return private_key, public_key


def read_private_key_from_file(private_key_path, key):
    with open(private_key_path, 'rb') as f:
        return RSA.import_key(f.read(), key)


def read_private_key(private_key_content, key):
    return RSA.import_key(private_key_content, key)


def read_public_key(public_key_content):
    return RSA.import_key(public_key_content)


# noinspection PyTypeChecker
def rsa_private_key_sign(private_key, message):
    signer = pkcs1_15.new(private_key)
    hashed_value = SHA256.new(message)
    signature = signer.sign(hashed_value)
    return signature


# noinspection PyTypeChecker,PyBroadException
def rsa_public_key_verify_signature(public_key, message, signature):
    verifier = pkcs1_15.new(public_key)
    hashed_value = SHA256.new(message)
    try:
        verifier.verify(hashed_value, signature)
        return True
    except Exception:
        return False


def rsa_private_key_decrypt(private_key, ciphertext):
    decipher = PKCS1_OAEP.new(private_key)
    return decipher.decrypt(ciphertext)


def rsa_public_key_encrypt(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def aes_encrypt(content, password):
    cipher = AES.new(password, AES.MODE_SIV)
    ciphertext, tag = cipher.encrypt_and_digest(content)

    return ciphertext, tag


def export_private_key(private_key, p_format="DER", passphrase=None, pkcs=8):
    return private_key.export_key(format=p_format, passphrase=passphrase, pkcs=pkcs)


def aes_decrypt(ciphertext, tag, password):
    cipher = AES.new(password, AES.MODE_SIV)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


def encrypt_request_data(data, secret):
    message, tag = aes_encrypt(json.dumps(data).encode(), secret)
    message = base64.urlsafe_b64encode(message).decode()
    tag = base64.urlsafe_b64encode(tag).decode()

    return message, tag


def decrypt_request_data(message, secret, tag):
    tag = base64.urlsafe_b64decode(tag)
    data = json.loads(aes_decrypt(base64.urlsafe_b64decode(message), tag, secret))

    return data


def create_inner_message(status, message=None, data=None, generate_garbage=True):
    content = {
        'status': status,
        'message': message,
        'data': data
    }
    if generate_garbage:
        content['garbage'] = base64.b64encode(os.urandom(8)).decode()
    return content


def message_wrapper(message, secret, status='OK'):
    ciphertext, tag = encrypt_request_data(message, secret)
    return {
        'message': ciphertext,
        'tag': tag,
        'status': status
    }


def message_unwrapper(message, secret, pop_garbage=True):
    ciphertext, tag = message['message'], message['tag']
    data = decrypt_request_data(ciphertext, secret, tag)
    if pop_garbage:
        data.pop('garbage', None)

    return data


def is_valid_wrapper(message):
    return message['status'] == 'OK'


def invalid_wrapper():
    return create_inner_message('INVALID WRAPPER')


def is_ttl_valid(ttl):
    now = datetime.now()
    return ttl > now.timestamp()


def scrypt_password(password, salt=None, key_len=64, N=2 ** 14):
    if salt is None:
        salt = get_random_bytes(key_len)
    return scrypt(password, salt, key_len, N=N, r=8, p=1), salt


def current_time(offset_in_days=None):
    now = datetime.now()
    if offset_in_days is not None:
        now += timedelta(days=offset_in_days)
    return now.timestamp()


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


def random_challenge(size=64):
    return os.urandom(size)


def show_blank_page_on_error(cherrypy):
    for key_value in cherrypy.request.cookie.keys():
        cherrypy.request.cookie[key_value] = ''
        cherrypy.request.cookie[key_value]['max-age'] = '0'
        cherrypy.request.cookie[key_value]['expires'] = '0'

    for key_value in cherrypy.response.cookie.keys():
        cherrypy.response.cookie[key_value] = ''
        cherrypy.response.cookie[key_value]['max-age'] = '0'
        cherrypy.response.cookie[key_value]['expires'] = '0'

    cherrypy.response.status = 500

    cherrypy.response.body = b'<html><head></head><body>INTERNAL ERROR</body></html>'
