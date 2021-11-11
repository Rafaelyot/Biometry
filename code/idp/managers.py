import base64
import os
import sqlite3

from utils import hash_password, read_private_key_from_file, aes_decrypt, read_public_key, rsa_public_key_encrypt, \
    rsa_public_key_verify_signature, rsa_private_key_sign, random_challenge, create_inner_message
from zkp_protocol import calc_result_bit, f


class CacheManager:
    def __init__(self):
        self.uid2user = {}
        self.user2uid = {}
        self.uid2key = {}
        self.uid2secret = {}
        self.uid2attributes = {}

    def clear_cache_by_uid(self, uid):
        user = self.uid2user.pop(uid, None)
        self.user2uid.pop(user, None)
        self.uid2key.pop(uid, None)
        self.uid2secret.pop(uid, None)
        self.uid2attributes.pop(uid, None)
        return user


class ZKPManager:
    def __init__(self):
        self.data = {}
        self.iterations_interval = (100, 1000)

    def negotiate_iterations(self, username, password, iterations_interval):  # DONE
        common_intervals = set(range(*self.iterations_interval)).intersection(set(range(*iterations_interval)))

        if len(common_intervals) == 0:
            return create_inner_message("NO AGREEMENT", "Invalid iterations interval")

        self.data[username] = {
            'password': password,
            'response': None,
            'iteration': 0,
            'max_iterations': max(common_intervals),
            'is_legit': True
        }
        return create_inner_message('OK', data={'iterations': self.data[username]['max_iterations']})

    def verify_r(self, username, r, is_legit):
        response = self.data[username]['response']
        if response is None:
            return True

        return calc_result_bit(response, is_legit) == r

    def invalidate_user(self, username):
        self.data.pop(username, None)

    def protocol(self, username, challenge, r):
        iteration = self.data[username]['iteration']
        is_legit = self.data[username]['is_legit']
        password = self.data[username]['password']

        response = f(challenge, password, self.data[username]['response'])
        incoming_r = calc_result_bit(response, is_legit)

        if is_legit:  # If once False always False
            in_iterations = iteration <= self.data[username]['max_iterations']
            self.data[username]['is_legit'] = self.verify_r(username, r, is_legit) and in_iterations

        new_challenge = random_challenge()
        self.data[username]['response'] = f(new_challenge, password, response)
        self.data[username]['iteration'] += 1

        return create_inner_message('OK', data={'challenge': base64.b64encode(new_challenge).decode(), 'r': incoming_r})


class DatabaseManager:
    def __init__(self, db_file, creation_script='idp/tables.sql'):
        self.db_file = db_file
        self.create_tables()
        self.creation_script_path = creation_script

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def create_tables(self):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()
            with open(self.creation_script_path) as sql_file:
                cursor.executescript(sql_file.read())

            con.commit()

    def create_user(self, username, email, password):
        password_hash = hash_password(password.encode())
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            try:
                user_id = int.from_bytes(os.urandom(7), 'big')
                cursor.execute('insert into users (id, username, email, password) values (?, ?, ?, ?)',
                               (user_id, username, email, password_hash))
                con.commit()
                return True
            except Exception as e:
                print(e)
                return False

    def get_user(self, username, as_dict=False):
        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = self.dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where username = ?', (username,)).fetchone()

            return user if user is not None else {}

    def get_public_key(self, public_key_id=None, as_dict=False):
        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = self.dict_factory
            cursor = con.cursor()

            public_key = cursor.execute('select * from  public_key where id = ?', (public_key_id,)).fetchone()

            return public_key if public_key is not None else {}

    def get_user_for_login(self, username_or_email, password):
        try:
            with sqlite3.connect(self.db_file) as con:
                con.row_factory = self.dict_factory
                cursor = con.cursor()
                user = cursor.execute('select * from users where username = ? or email = ?',
                                      (username_or_email, username_or_email)).fetchone()

                if hash_password(password.encode()) != user.pop('password', None):
                    return None

                return user or None
        except Exception as e:
            print(e)
            return None

    def get_user_by_id(self, user_id, as_dict=False):
        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = self.dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where id = ?', (user_id,)).fetchone()

            return user if user is not None else {}

    def add_public_key(self, username, public_key_content, ttl):
        try:
            with sqlite3.connect(self.db_file) as con:
                cursor = con.cursor()

                id_value = int.from_bytes(os.urandom(7), 'big')
                user_id = self.get_user(username, as_dict=True).get('id')
                if user_id is None:
                    return False, None

                cursor.execute('insert into public_key (id, user_id, public_key_content, public_key_ttl) '
                               'values (?,?,?,?)',
                               (id_value, user_id, public_key_content, ttl))

                con.commit()
            return True, id_value

        except Exception as e:
            print(e)
            return False, None

    def delete_public_key(self, public_key_id):
        try:
            with sqlite3.connect(self.db_file) as con:
                cursor = con.cursor()
                cursor.execute('delete from public_key where id = ?', (public_key_id,))
                con.commit()
            return True
        except Exception as e:
            print(e)
            return False

    def update_user(self, user_id, new_args, as_dict=False):
        try:
            if len(new_args) > 0:
                with sqlite3.connect(self.db_file) as con:
                    if as_dict:
                        con.row_factory = self.dict_factory
                    cursor = con.cursor()
                    query = []
                    for arg in new_args:
                        if arg == 'password':
                            new_args[arg] = hash_password(new_args['password'].encode())
                        query.append(f' {arg} = ?,')

                    if len(query) > 0:
                        query[-1] = query[-1][:-1]
                        cursor.execute(f'update users set {"".join(query)} where id = ?',
                                       (*list(new_args.values()), user_id,))
                    con.commit()
            return True
        except Exception as e:
            print(e)
            return False

    def delete_user(self, account_id):
        try:
            with sqlite3.connect(self.db_file) as con:
                con.row_factory = self.dict_factory
                cursor = con.cursor()
                cursor.execute('delete from users where id = ?', (account_id,))
                con.commit()
            return True

        except Exception as e:
            print(e)
            return False


class CryptographicManager:
    def __init__(self, private_key_path='pki_idp/private.pem'):
        self.data = {}
        self.private_key = read_private_key_from_file(private_key_path, None)

    def decrypt_and_verify_public_key(self, ciphertext, tag, key):
        return aes_decrypt(ciphertext, tag, key)

    def encrypt_with_public_key(self, public_key_content, plaintext):
        public_key = read_public_key(public_key_content)
        ciphertext = rsa_public_key_encrypt(public_key, plaintext)
        return base64.b64encode(ciphertext).decode()

    def verify_signature_with_public_key(self, public_key_content, message, signature):
        public_key = read_public_key(public_key_content)
        return rsa_public_key_verify_signature(public_key, message, signature)

    def sign_with_private_key(self, private_key, message):
        return base64.b64encode(rsa_private_key_sign(private_key, message)).decode()
