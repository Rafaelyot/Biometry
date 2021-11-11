import os
from Crypto.Hash import HMAC, SHA512


def f(challenge, password, previous_response=None):
    if previous_response is not None:
        previous_cipher = HMAC.new(password, previous_response, digestmod=SHA512)
        password = previous_cipher.digest()

    cipher = HMAC.new(password, challenge, digestmod=SHA512)

    return cipher.digest()


def calc_result_bit(response, is_legit=True):
    if is_legit:
        response = int.from_bytes(response, "big")
        return int(bin(response)[2:].count('1') % 2 == 0)
    else:
        return int.from_bytes(os.urandom(1), 'big') & 1



