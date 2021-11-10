from utils import hash_password, generate_rsa_keys, aes_encrypt, static_page, error_page, read_private_key, \
    rsa_private_key_decrypt, rsa_private_key_sign, is_ttl_valid, scrypt_password, aes_decrypt, encrypt_request_data, \
    decrypt_request_data, export_private_key
from zkp_protocol import calc_result_bit, f, random_challenge
from jinja2 import Environment, FileSystemLoader
from biometric_systems.facial.facial_recognition import recognition
import cherrypy
import requests
import base64
import os
import sqlite3
import json


class Cache(object):
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


class ZKP:
    def __init__(self):
        self.zkp_iterations_interval = (50, 500)

    def negotiate_iterations(self, secret, username, uid, url):
        data = {
            'garbage': base64.b64encode(os.urandom(8)).decode(),
            'username': username,
            'iterations_interval': self.zkp_iterations_interval
        }

        message, tag = encrypt_request_data(data, secret)

        received_data = requests.post(url, data={'message': message, 'tag': tag, 'uid': uid}).json()

        if received_data.get('status') == 'NO AGREEMENT':
            return {'status': 'NO AGREEMENT', 'idp_interval': received_data.get('interval')}

        if received_data.get('status') != 'OK':
            return received_data

        cipher_data, cipher_tag = received_data.pop('cipher_data', None), received_data.pop('cipher_tag', None)
        decrypted_message = decrypt_request_data(cipher_data, cipher_tag, secret)
        decrypted_message.pop('garbage', None)
        received_data.update(decrypted_message)

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

        return is_legit, response


# noinspection SqlResolve
class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.create_tables()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def create_tables(self):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            cursor.execute('''
                create table if not exists users (
                    id integer primary key,
                    username text not null unique,
                    email text not null unique,
                    master_password blob not null,
                    master_password_salt blob not null
                )
            ''')

            cursor.execute('''
                create table if not exists accounts (
                    id integer primary key,
                    user_id integer,
                    username text not null,
                    email text not null,
                    password blob not null,
                    password_tag blob not null,
                    authenticator text not null,
                    private_key blob,
                    private_key_ttl real,
                    private_key_password_salt blob,
                    public_key_id integer,
                    first_authentication INTEGER default 1,
                    foreign key (user_id) references users(id),
                    unique(username, email, authenticator)
                )
            ''')

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


class Cryptographic:
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


def show_blank_page_on_error():
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


@cherrypy.config(**{'request.error_response': show_blank_page_on_error})
class Application(object):
    def __init__(self):
        self.jinja_env = Environment(loader=FileSystemLoader('static'))
        self.cache = Cache()
        self.zkp_service = ZKP()
        self.database_service = Database('helper/helper.db')
        self.cryptographic_service = Cryptographic()
        self.idp_url = 'http://localhost:8082'
        self.data = {}
        self.temp = {}
        self.auth_error = "Authentication process failed. <br> This can occur because local credentials are wrong. " \
                          "Try to change this on <a href=\"http://localhost:8083\">http://localhost:8083</a>"

    def set_cookie(self, key, value):
        cookie = cherrypy.response.cookie
        cookie[key] = value
        cookie[key]['path'] = '/'
        cookie[key]['max-age'] = '20'
        cookie[key]['version'] = '1'

    def expire_cookie(self, key):
        cookie = cherrypy.response.cookie
        cookie[key] = ''
        cookie[key]['max-age'] = '0'
        cookie[key]['expires'] = '0'

    def zkp_authentication(self, secret, username, password, uid, account_id, master_password):
        zkp_iterations_data = self.zkp_service.negotiate_iterations(secret, username, uid,
                                                                    f'{self.idp_url}/zkp_iterations')

        if zkp_iterations_data.get('status') == 'NO AGREEMENT':
            return error_page('Invalid number of iterations')

        if zkp_iterations_data.get('status') != 'OK':
            return error_page(self.auth_error)

        status = zkp_iterations_data.pop('status', None)
        if status == 'OK':
            iterations = zkp_iterations_data.get('iterations')
            is_legit, response = self.zkp_service.protocol(secret, password, uid, iterations, f'{self.idp_url}/zkp')

            if is_legit:
                pub_key_reception_data = self.send_public_key(secret, uid, response, account_id, password,
                                                              master_password)
                pub_key_status = pub_key_reception_data.get('status')
                if pub_key_status == 'OK':
                    raise cherrypy.HTTPRedirect(f'/accounts?account_id={account_id}')

                else:
                    return error_page(self.auth_error)

            else:
                return error_page(self.auth_error)

        elif status == 'NO USER':
            raise cherrypy.HTTPRedirect('/add_idp_account')

        else:
            return error_page(self.auth_error)

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

    # API ENDPOINTS
    @cherrypy.expose
    def index(self, uid=None, secret=None):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        req_id = self.cache.user_id2req_id.get(user_id, None)
        idp_id = self.cache.req_id2identity_attribute_data.get(req_id, {}).get('idp_info', {}).get('id')
        if uid is not None and secret is not None and idp_id is not None:
            self.cache.user_id2uid[user_id] = uid
            self.data = {
                'uid': uid,
                'secret': secret,
                'idp_id': idp_id,
            }

        raise cherrypy.HTTPRedirect('/accounts')

    @cherrypy.expose
    def logout(self):
        # Clear session
        cherrypy.session.clear()
        raise cherrypy.HTTPRedirect('/')

    # Create new account
    @cherrypy.expose
    def sign_up(self):
        return static_page('sign_up.html')

    @cherrypy.expose
    def create_account(self, username, email, master_password):
        creation_status = self.database_service.create_user(username, email, master_password)

        if not creation_status:
            return error_page('Error creating the new user')

        raise cherrypy.HTTPRedirect('/login')

    # # # # #

    # Login
    @cherrypy.expose
    def login(self):
        return static_page('login.html')

    @cherrypy.expose
    def authenticate_key_chain(self, username_or_email, master_password):
        user = self.database_service.get_user_for_login(username_or_email, username_or_email, master_password)
        if not user:
            return error_page('Wrong credentials')

        cherrypy.session['user_id'] = user.get('id')
        raise cherrypy.HTTPRedirect('/accounts')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def erase_authentication_process(self):
        self.data.pop('uid', None)
        self.data.pop('idp_id', None)
        self.data.pop('secret', None)
        return {'status': 'OK'}

    # # # # #

    # IDP Accounts per user
    @cherrypy.expose
    def accounts(self, account_id=None):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        authenticate = False

        uid, idp_id = self.data.get('uid', None), self.data.get('idp_id', None)
        secret = self.data.get('secret', None)
        req_id = self.cache.user_id2req_id.get(user_id)

        if account_id is not None and uid is None and idp_id is None and secret is None:
            return error_page(self.auth_error)

        if uid is not None and idp_id is not None and secret is not None and req_id is not None:
            authenticate = True
            if account_id:
                # Delete current authentication process data
                if not self.database_service.first_authentication(account_id):
                    self.data.pop('uid', None), self.data.pop('idp_id', None), self.data.pop('secret', None)
                secret = base64.urlsafe_b64decode(secret)
                cherrypy.session['uid'] = uid  # Save uid in client session

                master_password = self.database_service.get_user_by_id(user_id).get('master_password')

                account = self.database_service.get_account_by_id_minimal(account_id, master_password)
                if not account:
                    raise cherrypy.HTTPRedirect('/add_idp_account')

                username, password = account.get('username'), hash_password(account.get('password').encode())

                if self.database_service.get_private_key(account_id, as_dict=True).get('private_key') is not None:
                    page, status = self.identity_attributes_protocol(secret, account_id, master_password, username,
                                                                     password, uid, req_id)
                    if not status:
                        return self.zkp_authentication(secret, username, password, uid, account_id, master_password)
                    return page
                else:
                    return self.zkp_authentication(secret, username, password, uid, account_id, master_password)

        template = self.jinja_env.get_template('accounts.html')
        return template.render(authenticate=True, idp_url=self.idp_url)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def credentials(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        master_password = self.database_service.get_user_by_id(user_id).get('master_password')
        data = self.database_service.get_accounts(user_id, master_password)
        for i in range(len(data)):
            data[i]['id'] = str(data[i]['id'])
        return data

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def save_tmp_credentials(self, **kwargs):
        self.temp.clear()
        self.temp.update(kwargs)
        return {'status': 'OK'}

    # # # # #

    # Create new idp account
    @cherrypy.expose
    def add_idp_account(self, **kwargs):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        carried = bool(int(kwargs.get('carried', '0')))
        temp_credentials = {}
        if carried:
            temp_credentials = dict(self.temp)

        self.temp.clear()
        template = self.jinja_env.get_template('create_idp_account.html')
        return template.render(**temp_credentials)

    @cherrypy.expose
    def create_idp_account(self, username, email, password, authenticator):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        master_password = self.database_service.get_user_by_id(user_id).get('master_password')
        account_creation_status = self.database_service.create_account(user_id, master_password, username, email,
                                                                       password, authenticator)
        if account_creation_status:
            raise cherrypy.HTTPRedirect('/accounts')

        return error_page('Error creating idp account')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def update_idp_account(self, account_id, **kwargs):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        master_password = self.database_service.get_user_by_id(user_id).get('master_password')
        account = self.database_service.get_account_by_id(account_id, master_password)
        new_args = {}
        for k, v in kwargs.items():
            if account[k] == v or len(v) == 0:
                continue
            new_args[k] = v

        if len(new_args) == 0:
            return {'status': 'NOTHING'}

        old_password, old_salt = account.get('password').encode(), account.get('private_key_password_salt')
        # User update
        user_update_status = self.database_service.update_account(account_id, master_password, new_args)
        if not user_update_status:
            return {'status': 'ERROR', 'message': 'Error updating local user info'}

        # Private key update
        if 'password' in new_args:
            private_key_content = account.get('private_key')
            if private_key_content is not None:
                new_password = hash_password(new_args.get('password').encode())

                new_private_key_content, new_salt = self.cryptographic_service.update_private_key_cipher(
                    private_key_content,
                    master_password + hash_password(old_password),
                    old_salt, master_password + new_password)

                if not new_private_key_content:
                    return {'status': 'ERROR', 'message': 'Error updating private key'}

                update_private_key_status = self.database_service.update_private_key(account_id,
                                                                                     new_private_key_content,
                                                                                     new_salt)
                if not update_private_key_status:
                    return {'status': 'ERROR', 'message': 'Error saving updated private key'}

        self.database_service.set_first_authentication(account_id, 1)
        return {'status': 'OK'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def delete_account(self, account_id):
        removal_status = self.database_service.delete_account(account_id)
        if removal_status:
            return {'status': 'OK'}
        else:
            return {'status': 'ERROR'}

    # # # # #

    # Receive sp identity request endpoint
    @cherrypy.expose
    def sp_identity_request(self, query, req_id):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        data = json.loads(base64.urlsafe_b64decode(query).decode())
        self.cache.user_id2req_id[user_id] = req_id
        self.cache.req_id2identity_attribute_data[req_id] = data

        info = {
            'sp_id': data.get('sp_info', {}).get('id'),
            'idp_id': data.get('idp_info', {}).get('id'),
            'arguments': ', '.join(data.get('identity_attributes', []))
        }
        template = self.jinja_env.get_template('sp_request_consent.html')
        return template.render(**info)

    @cherrypy.expose
    def handle_identity_response(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        uid = self.cache.user_id2uid.get(user_id)
        req_id = self.cache.user_id2req_id.get(user_id)
        attributes = self.cache.uid2identity_data.get(uid)
        identity_attributes = self.cache.req_id2identity_attribute_data.get(req_id, {})
        query = base64.urlsafe_b64encode(json.dumps(attributes).encode()).decode()
        self.cache.clear_by_userid(user_id)
        self.data.clear()

        sp_url = identity_attributes.get('sp_info', {}).get('location')

        if sp_url is None:
            raise cherrypy.HTTPRedirect('/')
        raise cherrypy.HTTPRedirect(f'{sp_url}?query={query}', 303)

    @cherrypy.expose
    def gather_authentication_key(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        req_id = self.cache.user_id2req_id.get(user_id, None)
        data = self.cache.req_id2identity_attribute_data.get(req_id, None)
        if req_id is None or data is None:
            self.cache.clear_by_userid(user_id)
            raise cherrypy.HTTPRedirect('/')

        idp_location = data.get('idp_info', {}).get('location')
        if idp_location is None:
            self.cache.clear_by_userid(user_id)
            raise cherrypy.HTTPRedirect('/')

        raise cherrypy.HTTPRedirect(f'{self.idp_url}/generate_key?req_id={req_id}', 303)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def request_consent_action(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            return {'status': 'ERROR'}

        confirmation = cherrypy.request.json.get('confirmation', False)
        if not confirmation:
            self.cache.clear_by_userid(user_id)
            return {'status': 'OK', 'operation': False}

        req_id = self.cache.user_id2req_id.get(user_id, None)
        data = self.cache.req_id2identity_attribute_data.get(req_id, None)
        if req_id is None or data is None:
            return {'status': 'NO_REQUEST'}

        return {'status': 'OK', 'operation': True}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def response_consent_action(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            return {'status': 'ERROR'}

        confirmation = cherrypy.request.json.get('confirmation', False)
        if not confirmation:
            self.cache.clear_by_userid(user_id)
            return {'status': 'OK', 'operation': False}

        req_id = self.cache.user_id2req_id.get(user_id, None)
        data = self.cache.req_id2identity_attribute_data.get(req_id, None)
        if req_id is None or data is None:
            return {'status': 'NO_REQUEST'}

        return {'status': 'OK', 'operation': True}

    @cherrypy.expose
    def biometric_authentication(self):
        recognition()


server_config = {
    'server.socket_host': 'localhost',
    'server.socket_port': 8083,
    'server.thread_pool': 50,
    'tools.sessions.on': True,
    'tools.sessions.storage_type': "File",
    'tools.sessions.storage_path': 'helper/sessions',
    'tools.sessions.timeout': 60,
    'tools.sessions.clean_freq': 10,
    'tools.sessions.name': 'helper_session_id'
}
cherrypy.config.update(server_config)
cherrypy.quickstart(Application())
