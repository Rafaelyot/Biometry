import base64
import os
import requests
import sqlite3

from utils import create_inner_message, encrypt_request_data, decrypt_request_data, random_challenge, scrypt_password, \
    aes_encrypt, aes_decrypt, generate_rsa_keys, read_private_key, rsa_private_key_decrypt, rsa_private_key_sign, \
    export_private_key, message_unwrapper, message_wrapper, is_valid_wrapper, invalid_wrapper
from zkp_protocol import f, calc_result_bit


class CacheManager:
    def __init__(self):
        self.req_id2identity_attribute_data = {}
        self.uid2identity_data = {}
        self.user_id2req_id = {}
        self.user_id2uid = {}

    def clear_by_userid(self, userid):
        req_id = self.user_id2req_id.pop(userid, None)
        uid = self.user_id2uid.pop(userid, None)
        self.req_id2identity_attribute_data.pop(req_id, None)
        self.uid2identity_data.pop(uid, None)


class ZKPManager:
    def __init__(self):
        self.zkp_iterations_interval = (50, 500)

    def negotiate_iterations(self, secret, username, uid, url):  # DONE
        inner_data = create_inner_message("START ZKP ITERATIONS", data={
            'username': username,
            'iterations_interval': self.zkp_iterations_interval
        })

        data, tag = message_wrapper(inner_data, secret)

        received_data = requests.post(url, data={'data': data, 'uid': uid}).json()
        if not is_valid_wrapper(received_data):
            return invalid_wrapper()
        
        received_data = message_unwrapper(received_data, secret)

        return received_data

    def protocol(self, secret, password, uid, iterations, url):
        response = None
        r = 0
        is_legit = True
        for i in range(iterations):
            new_challenge = random_challenge()
            response = f(new_challenge, password, response)
            data = {
                'garbage': base64.b64encode(os.urandom(8)).decode(),
                'challenge': base64.b64encode(new_challenge).decode(),
                'r': r
            }

            message, tag = encrypt_request_data(data, secret)
            request_data = {
                'message': message,
                'tag': tag,
                'uid': uid
            }
            incoming_data = requests.post(url, data=request_data).json()
            cipher_data, cipher_tag = incoming_data.pop('cipher_data', None), incoming_data.pop('cipher_tag', None)
            decrypted_message = decrypt_request_data(cipher_data, cipher_tag, secret)
            decrypted_message.pop('garbage', None)
            incoming_data.update(decrypted_message)

            if incoming_data.get('status') != 'OK':
                is_legit = False
                response = None
                break

            if is_legit:  # If once False always False
                is_legit = (calc_result_bit(response) == incoming_data.get('r', -1))

            response = f(base64.b64decode(incoming_data.get('challenge', 0)), password, response)
            r = calc_result_bit(response, is_legit)

        return {'status': 'OK' if is_legit else 'NOT LEGIT', 'response': response}  # is_legit, response


# noinspection SqlResolve
class DatabaseManager:
    def __init__(self, db_file, creation_script):
        self.db_file = db_file
        self.creation_script = creation_script
        self.create_tables()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def create_tables(self):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            with open(self.creation_script) as sql_file:
                cursor.executescript(sql_file.read())

            con.commit()

    def create_user(self, username, email, master_password):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            try:
                password_hash, password_salt = scrypt_password(master_password.encode())
                id_value = int.from_bytes(os.urandom(7), 'big')
                cursor.execute('insert into users (id, username, email, master_password, master_password_salt) '
                               'values (?, ?, ?, ?, ?)',
                               (id_value, username, email, password_hash, password_salt))
                con.commit()
                return True
            except Exception as e:
                print(e)
                return False

    def create_account(self, user_id, master_password, username, email, password, authenticator):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            try:
                password_cipher, password_tag = aes_encrypt(password.encode(), master_password)
                id_value = int.from_bytes(os.urandom(7), 'big')

                cursor.execute(
                    'insert into accounts (id, user_id, username, email, password, password_tag, authenticator) '
                    'values (?, ?, ?, ?, ? ,?, ?)',
                    (id_value, user_id, username, email, password_cipher, password_tag, authenticator))
                con.commit()
                return True
            except Exception as e:
                print(e)
                return False

    def get_user_by_id(self, user_id):
        with sqlite3.connect(self.db_file) as con:
            con.row_factory = self.dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where id = ?', (user_id,)).fetchone()

            return user if user is not None else {}

    def get_user_for_login(self, username, email, master_password=None):
        with sqlite3.connect(self.db_file) as con:
            con.row_factory = self.dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where username = ? or email = ?', (username, email)).fetchone()

            if user is None:
                user = {}

            if master_password is not None and user is not None:
                user_master_password = user.get('master_password')
                user_master_password_salt = user.get('master_password_salt')
                if user_master_password != scrypt_password(master_password.encode(), user_master_password_salt)[0]:
                    return {}

            return user

    def get_accounts(self, user_id, master_password, authenticator=None):
        with sqlite3.connect(self.db_file) as con:
            con.row_factory = self.dict_factory
            cursor = con.cursor()

            if authenticator is None:
                accounts = cursor.execute('select * from accounts where user_id = ?', (user_id,)).fetchall()
            else:
                accounts = cursor.execute('select * from accounts where user_id = ? and authenticator = ?',
                                          (user_id, authenticator,)).fetchall()

            for i, account in enumerate(accounts):
                account['password'] = aes_decrypt(account.get('password'), account.get('password_tag'),
                                                  master_password).decode()
                account.pop('password_tag', None)
                account.pop('user_id', None)
                account.pop('private_key', None)
                account.pop('private_key_ttl', None)
                account.pop('private_key_password_salt', None)
                account.pop('public_key_id', None)

                accounts[i] = account

            return accounts

    def get_private_key(self, account_id, as_dict=False):
        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = self.dict_factory
            cursor = con.cursor()

            private_key = cursor.execute('select private_key, private_key_ttl, private_key_password_salt, '
                                         'public_key_id from accounts where id = ?',
                                         (account_id,)).fetchone()
            return private_key if private_key is not None else {}

    def add_private_key(self, account_id, private_key_content, private_key_ttl, private_key_password_salt,
                        public_key_id):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()
            try:
                cursor.execute(
                    'update accounts set private_key = ?, private_key_ttl = ?, private_key_password_salt = ?, public_key_id = ?'
                    'where id = ?',
                    (private_key_content, private_key_ttl, private_key_password_salt, public_key_id, account_id))
                con.commit()
                return True
            except Exception as e:
                print(e)
                return False

    def delete_private_key(self, account_id):
        with sqlite3.connect(self.db_file) as con:
            try:
                cursor = con.cursor()
                cursor.execute(
                    'update accounts set private_key = ?, private_key_ttl = ?, private_key_password_salt = ?, public_key_id = ?'
                    'where id = ?',
                    (None, None, None, None, account_id))
                con.commit()
                return True

            except Exception:
                return False

    def get_account_by_id(self, account_id, master_password):
        with sqlite3.connect(self.db_file) as con:
            con.row_factory = self.dict_factory
            cursor = con.cursor()
            account = cursor.execute('select * from accounts where id = ?', (account_id,)).fetchone()
            if account:
                account['password'] = aes_decrypt(account.get('password'), account.get('password_tag'),
                                                  master_password).decode()

            return account or {}

    def get_account_by_id_minimal(self, account_id, master_password):
        try:

            account = self.get_account_by_id(account_id, master_password)
            account.pop('password_tag', None)
            account.pop('user_id', None)
            account.pop('private_key', None)
            account.pop('private_key_ttl', None)
            account.pop('private_key_password_salt', None)
            account.pop('public_key_id', None)

            return account or {}
        except Exception:
            return {}

    def first_authentication(self, account_id):
        try:
            with sqlite3.connect(self.db_file) as con:
                con.row_factory = self.dict_factory
                cursor = con.cursor()
                status = cursor.execute('select first_authentication from accounts where id = ?',
                                        (account_id,)).fetchone().get('first_authentication')

                if bool(status):
                    cursor.execute('update accounts set first_authentication = ? where id = ?', (0, account_id))
                con.commit()
            return bool(status)
        except Exception:
            return False

    def set_first_authentication(self, account_id, status):
        try:
            with sqlite3.connect(self.db_file) as con:
                cursor = con.cursor()
                cursor.execute('update accounts set first_authentication = ? where id = ?', (status, account_id))
                con.commit()
            return True
        except Exception:
            return False

    def update_account(self, account_id, master_password, new_args):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            try:
                if len(new_args) > 0:
                    u_query = []
                    for arg in list(new_args.keys()):
                        if arg == 'password':
                            password_cipher, password_tag = aes_encrypt(new_args['password'].encode(), master_password)
                            cursor.execute(f'update accounts set password = ?, password_tag = ?  where id = ?',
                                           (password_cipher, password_tag, account_id,))
                            new_args.pop(arg, None)
                        else:
                            u_query.append(f' {arg} = ?,')
                    if len(u_query) > 0:
                        u_query[-1] = u_query[-1][:-1]
                        cursor.execute(f'update accounts set {"".join(u_query)} where id = ?',
                                       (*list(new_args.values()), account_id,))
                    con.commit()
                return True
            except Exception as e:
                print(e)
                return False

    def update_private_key(self, account_id, private_key_content, private_key_password_salt, as_dict=False):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()
            try:
                cursor.execute('update accounts set private_key = ?, private_key_password_salt = ? where id = ?',
                               (private_key_content, private_key_password_salt, account_id,))
                con.commit()
                return True
            except Exception:
                return False

    def delete_account(self, account_id):
        try:
            with sqlite3.connect(self.db_file) as con:
                cursor = con.cursor()
                cursor.execute('delete from accounts where id = ?', (account_id,))
                con.commit()
            return True
        except Exception:
            return False


class CryptographicManager:
    def generate_asymmetric_credentials(self, key, authentication_key):
        private_key, public_key = generate_rsa_keys(key)
        cipher_public_key, tag = aes_encrypt(public_key, authentication_key)

        public_key = base64.b64encode(cipher_public_key).decode()
        tag = base64.b64encode(tag).decode()

        return private_key, public_key, tag

    def decrypt_with_private_key(self, private_key_content, key, ciphertext, salt):
        derived_key, _ = scrypt_password(key, salt=salt)
        try:
            private_key = read_private_key(private_key_content, derived_key)
            if private_key:
                return rsa_private_key_decrypt(private_key, ciphertext)

            return None

        except Exception:
            return None

    def sign_with_private_key(self, private_key_content, key, message, salt):
        try:
            derived_key, _ = scrypt_password(key, salt=salt)
            private_key = read_private_key(private_key_content, derived_key)
            if private_key:
                return base64.b64encode(rsa_private_key_sign(private_key, message)).decode()
        except Exception:
            return None

    def update_private_key_cipher(self, private_key_content, key, salt, new_key):
        try:
            derived_key, _ = scrypt_password(key, salt=salt)
            private_key = read_private_key(private_key_content, derived_key)

            new_derived_key, new_salt = scrypt_password(new_key)
            new_private_key_content = export_private_key(private_key, passphrase=new_derived_key)

            return new_private_key_content, new_salt
        except Exception:
            return None, None


class DispatcherManager:
    def __init__(self, idp_url):
        self.idp_url = idp_url

    def send_public_key(self, secret, uid, response, account_id, password, master_password):
        derived_password, salt = scrypt_password(master_password + password)
        private_key, public_key, tag = self.cryptographic_service.generate_asymmetric_credentials(derived_password,
                                                                                                  response)

        data = {
            'garbage': base64.b64encode(os.urandom(8)).decode(),
            'public_key': public_key,
            'tag': tag
        }

        message, tunnel_tag = encrypt_request_data(data, secret)

        request_data = {
            'message': message,
            'tag': tunnel_tag,
            'uid': uid
        }

        pub_key_reception_data = requests.post(f'{self.idp_url}/pub_key_receptor', data=request_data).json()
        cipher_data = pub_key_reception_data.pop('cipher_data', None)
        cipher_tag = pub_key_reception_data.pop('cipher_tag', None)
        decrypted_message = decrypt_request_data(cipher_data, cipher_tag, secret)
        decrypted_message.pop('garbage', None)
        pub_key_reception_data.update(decrypted_message)

        message = pub_key_reception_data.get('message')
        if pub_key_reception_data.get('status') == 'OK':
            ttl = pub_key_reception_data.get('ttl')
            public_key_id = pub_key_reception_data.get('public_key_id')
            if not self.database_service.add_private_key(account_id, private_key, ttl, salt, public_key_id):
                return {'status': 'ERROR', 'message': "Error saving the private key locally"}

        else:
            return {'status': 'ERROR', 'message': f'Error sending the public key to the IDP -> {message}'}

        return pub_key_reception_data

    def zkp_authentication(self, zkp_service, secret, username, password, uid, account_id, master_password):
        """
        Iterations
        """
        zkp_iterations_data = zkp_service.negotiate_iterations(secret, username, uid, f'{self.idp_url}/zkp_iterations')

        if (zkp_iteration_status := zkp_iterations_data.get('status')) != 'OK':
            return zkp_iteration_status

        """
        ZKP
        protocol
        execution
        """
        iterations = zkp_iterations_data.get('iterations')
        zkp_protocol_data = zkp_service.protocol(secret, password, uid, iterations, f'{self.idp_url}/zkp')

        if (zkp_protocol_status := zkp_protocol_data.get('status')) != 'OK':
            return zkp_protocol_status

        """
        Public
        key
        's dispatch
        """
        response = zkp_protocol_status.get('response')
        pub_key_reception_data = self.send_public_key(secret, uid, response, account_id, password, master_password)

        return pub_key_reception_data.get('status')

    def identity_attributes_protocol(self, secret, account_id, master_password, username, password, uid, req_id):
        pki = self.database_service.get_private_key(account_id, as_dict=True)
        private_key_content, private_key_ttl = pki.get('private_key'), pki.get('private_key_ttl')
        public_key_id, private_key_password_salt = pki.get('public_key_id'), pki.get('private_key_password_salt')

        if not private_key_content:
            return error_page(self.auth_error), False

        if not is_ttl_valid(private_key_ttl):
            self.database_service.delete_private_key(account_id)
            raise cherrypy.HTTPRedirect('/accounts', 307)

        identity_attributes = self.cache.req_id2identity_attribute_data.get(req_id, {}).get('identity_attributes', [])
        identity_attributes_signature = self.cryptographic_service.sign_with_private_key(private_key_content,
                                                                                         master_password + password,
                                                                                         base64.b64encode(json.dumps(
                                                                                             identity_attributes).encode()),
                                                                                         private_key_password_salt)
        data = {
            'garbage': base64.b64encode(os.urandom(8)).decode(),
            'public_key_id': public_key_id,
            'username': username,
            'attributes': identity_attributes,
            'attributes_signature': identity_attributes_signature,
            'status': 'ATTRIBUTES_REQUEST'
        }

        message, tag = encrypt_request_data(data, secret)
        request_data = {
            'message': message,
            'tag': tag,
            'uid': uid,
        }

        response_data = requests.post(f'{self.idp_url}/handle_identity_request', data=request_data).json()
        if response_data.get('status') != 'OK':
            return error_page(self.auth_error), False

        data = response_data.get('data', {})
        cipher_data = data.pop('cipher_data', None)
        cipher_tag = data.pop('cipher_tag', None)
        decrypted_message = decrypt_request_data(cipher_data, cipher_tag, secret)
        decrypted_message.pop('garbage', None)
        data.update(decrypted_message)
        p_secret_cipher = base64.b64decode(data.get('secret'))
        p_secret = self.cryptographic_service.decrypt_with_private_key(private_key_content,
                                                                       master_password + password,
                                                                       p_secret_cipher, private_key_password_salt)
        attributes, attributes_tag = data.get('attributes'), data.get('attributes_tag')
        attributes = decrypt_request_data(attributes, attributes_tag, p_secret)
        h_attr = base64.b64decode(attributes.get('h_attr'))

        u = self.database_service.get_account_by_id(account_id, master_password)

        w_u = {
            'email': u.get('email', ''),
            'password': base64.b64encode(hash_password(u.get('password', '').encode())).decode()
        }
        hashed_attr = hash_password(json.dumps(w_u).encode())

        if h_attr != hashed_attr:
            return error_page(self.auth_error), False

        self.cache.uid2identity_data[uid] = attributes
        identity_attribute_data = self.cache.req_id2identity_attribute_data[req_id]
        info = {
            'sp_id': identity_attribute_data.get('sp_info', {}).get('id'),
            'idp_id': identity_attribute_data.get('idp_info', {}).get('id'),
            'attributes': attributes.get('attributes', {})
        }
        template = self.jinja_env.get_template('response_consent.html')
        return template.render(**info), True
