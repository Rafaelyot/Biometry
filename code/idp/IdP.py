import os

import cherrypy
import sqlite3
import base64
import json
import requests
from utils import hash_password, aes_decrypt, error_page, current_time, rsa_public_key_encrypt, \
    rsa_public_key_verify_signature, read_public_key, is_ttl_valid, decrypt_request_data, encrypt_request_data, \
    read_private_key_from_file, rsa_private_key_sign
from zkp_protocol import random_challenge, calc_result_bit, f
from saml2.s_utils import rndstr
from jinja2 import Environment, FileSystemLoader


class Cache(object):
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


class ZKP:
    def __init__(self):
        self.data = {}
        self.iterations_interval = (100, 1000)

    def negotiate_iterations(self, username, password, iterations_interval):
        common_intervals = set(range(*self.iterations_interval)).intersection(set(range(*iterations_interval)))

        if len(common_intervals) > 0:
            self.data[username] = {
                'password': password,
                'response': None,
                'iteration': 0,
                'max_iterations': max(common_intervals),  # MAX OR random??
                'is_legit': True
            }
            return {"status": "OK", 'iterations': self.data[username]['max_iterations']}

        else:
            return {"STATUS": "NO AGREEMENT", "message": "Invalid iterations interval"}

    def verify_r(self, username, r, iteration, is_legit):
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
            self.data[username]['is_legit'] = self.verify_r(username, r, iteration - 1, is_legit) and in_iterations

        new_challenge = random_challenge()
        self.data[username]['response'] = f(new_challenge, password, response)
        self.data[username]['iteration'] += 1

        return {'challenge': base64.b64encode(new_challenge).decode(), 'r': incoming_r, 'status': 'OK'}


# noinspection SqlResolve
class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.create_tables()

    def create_tables(self):
        with sqlite3.connect(self.db_file) as con:
            cursor = con.cursor()

            cursor.execute('''
                create  table if not exists users (
                    id integer primary key,
                    username text not null unique,
                    email text not null unique,
                    password blob not null
                )
            ''')

            cursor.execute('''
            create table if not exists public_key (
                id integer primary key ,
                user_id integer ,
                public_key_content blob,
                public_key_ttl real,
                foreign key (user_id) references users(id)
                )
            ''')

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

    def get_user(self, username, as_dict=False):
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where username = ?', (username,)).fetchone()

            return user if user is not None else {}

    def get_public_key(self, public_key_id=None, as_dict=False):
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = dict_factory
            cursor = con.cursor()

            public_key = cursor.execute('select * from  public_key where id = ?', (public_key_id,)).fetchone()

            return public_key if public_key is not None else {}

    def delete_public_key(self, public_key_id):
        try:
            with sqlite3.connect(self.db_file) as con:
                cursor = con.cursor()
                cursor.execute('delete from public_key where id = ?', (public_key_id,))
                con.commit()
            return True
        except Exception:
            return False

    def get_user_for_login(self, username_or_email, password):
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        try:
            with sqlite3.connect(self.db_file) as con:
                con.row_factory = dict_factory
                cursor = con.cursor()
                user = cursor.execute('select * from users where username = ? or email = ?',
                                      (username_or_email, username_or_email)).fetchone()

                if hash_password(password.encode()) != user.pop('password', None):
                    return None

                return user or None
        except Exception:
            return None

    def get_user_by_id(self, user_id, as_dict=False):
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        with sqlite3.connect(self.db_file) as con:
            if as_dict:
                con.row_factory = dict_factory
            cursor = con.cursor()
            user = cursor.execute('select * from users where id = ?', (user_id,)).fetchone()

            return user if user is not None else {}

    def update_user(self, user_id, new_args, as_dict=False):
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        try:
            if len(new_args) > 0:
                with sqlite3.connect(self.db_file) as con:
                    if as_dict:
                        con.row_factory = dict_factory
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
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        try:
            with sqlite3.connect(self.db_file) as con:
                con.row_factory = dict_factory
                cursor = con.cursor()
                cursor.execute('delete from users where id = ?', (account_id,))
                con.commit()
            return True

        except Exception:
            return False


class Cryptographic:
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
class IdP(object):
    def __init__(self):
        self.database_service = Database('idp/idp.db')
        self.zkp_service = ZKP()
        self.cryptographic_service = Cryptographic()
        self.cache = Cache()
        self.helper_url = 'http://localhost:8083'
        self.jinja_env = Environment(loader=FileSystemLoader('static'))

    def static_contents(self, path):
        return open('static/' + path, 'r').read()

    @cherrypy.expose
    def index(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        raise cherrypy.HTTPRedirect('/account')

    @cherrypy.expose
    def login(self):
        return self.static_contents('login_idp.html')

    @cherrypy.expose
    def authenticate(self, username_or_email, password):
        user = self.database_service.get_user_for_login(username_or_email, password)
        if not user:
            return error_page('Wrong credentials')

        cherrypy.session['user_id'] = user.get('id')
        raise cherrypy.HTTPRedirect('/account')

    @cherrypy.expose
    def sign_up(self):
        return self.static_contents('sign_up_idp.html')

    @cherrypy.expose
    def logout(self):
        # Clear session
        cherrypy.session.clear()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def account(self):
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        user = self.database_service.get_user_by_id(user_id, as_dict=True)
        username, email, password = user.get('username'), user.get('email'), user.get('password')

        template = self.jinja_env.get_template('accounts_idp.html')
        return template.render(username=username, email=email, password=password, id=user_id)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_account(self, username, email, password):
        account_id = self.database_service.create_user(username, email, password)

        requests.post('http://localhost:8083/save_tmp_credentials', data={
            'username': username,
            'email': email,
            'password': password,
            'idp': 'http://localhost:8082'
        })

        if account_id is not None:
            return {'status': 'OK', 'account_id': account_id}
        else:
            return {'status': 'ERROR'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def update_account(self, user_id, password, **kwargs):
        saved_user = self.database_service.get_user_by_id(user_id, as_dict=True)
        if not self.database_service.get_user_for_login(saved_user.get('username'), password):
            return {'status': 'ERROR', 'message': 'Wrong password'}

        kwargs['password'] = kwargs.pop('new_password', None)

        new_args = {}
        for k, v in kwargs.items():
            if k == "password" and saved_user.get(k) == hash_password(v.encode()):
                continue
            if saved_user.get(k) == v or len(v) == 0:
                continue
            new_args[k] = v

        if len(new_args) == 0:
            return {'status': 'NOTHING'}

        update_status = self.database_service.update_user(user_id, new_args)
        if update_status:
            return {'status': 'OK'}
        else:
            return {'status': 'ERROR', 'message': 'Error while updating credentials'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def delete_account(self, account_id):
        removal_status = self.database_service.delete_user(account_id)
        if removal_status:
            return {'status': 'OK'}
        else:
            return {'status': 'ERROR'}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def zkp_iterations(self, message, tag, uid):
        try:
            secret = self.cache.uid2secret[uid]
            data = decrypt_request_data(message, tag, secret)

            try:
                username = data['username']
                iterations_interval = data['iterations_interval']
                user = self.database_service.get_user(username, as_dict=True)
                if not user:
                    self.cache.clear_cache_by_uid(uid)
                    return {'status': 'NO USER', 'message': f'User {username} does not exists in IDP'}

                password = user.get('password')
                zpk_iterations_data = self.zkp_service.negotiate_iterations(username, password, iterations_interval)
                if zpk_iterations_data.get('status') == 'NO AGREEMENT':
                    return {'status': 'NO AGREEMENT', 'interval': self.zkp_service.iterations_interval}

                if zpk_iterations_data.get('status') == 'OK':
                    # Map between uid and username for further requests
                    self.cache.uid2user[uid] = username
                    self.cache.user2uid[username] = uid
                    protocol_data = {
                        'iterations': zpk_iterations_data.pop('iterations', None),
                        'garbage': base64.b64encode(os.urandom(8)).decode()
                    }
                    cipher_data, cipher_tag = encrypt_request_data(protocol_data, secret)
                    zpk_iterations_data['cipher_data'], zpk_iterations_data['cipher_tag'] = cipher_data, cipher_tag

                    return zpk_iterations_data

            except KeyError:
                self.cache.clear_cache_by_uid(uid)
                return {"status": "ERROR", "message": "Invalid arguments"}

        except Exception as e:
            self.zkp_service.invalidate_user(self.cache.clear_cache_by_uid(uid))
            return {'status': 'ERROR', "message": str(e)}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def zkp(self, message, tag, uid):
        try:
            secret = self.cache.uid2secret[uid]
            data = decrypt_request_data(message, tag, secret)

            challenge, r = data.get('challenge'), data.get('r')

            username = self.cache.uid2user[uid]
            zkp_data = self.zkp_service.protocol(username, base64.b64decode(challenge), r)

            protocol_data = {
                'challenge': zkp_data.pop('challenge', None),
                'r': zkp_data.pop('r', None),
                'garbage': base64.b64encode(os.urandom(8)).decode()
            }
            cipher_data, cipher_tag = encrypt_request_data(protocol_data, secret)
            zkp_data['cipher_data'], zkp_data['cipher_tag'] = cipher_data, cipher_tag

            return zkp_data
        except Exception as e:
            username = self.cache.clear_cache_by_uid(uid)
            self.zkp_service.invalidate_user(username)
            return {"status": "ERROR", "message": str(e)}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def pub_key_receptor(self, message, tag, uid):

        try:
            secret = self.cache.uid2secret[uid]
            data = decrypt_request_data(message, tag, secret)
            username = self.cache.uid2user[uid]

            max_iterations = self.zkp_service.data[username]['max_iterations']
            current_iteration = self.zkp_service.data[username]['iteration']
            response = self.zkp_service.data[username]['response']

            self.zkp_service.invalidate_user(username)
            if max_iterations != current_iteration:
                self.cache.clear_cache_by_uid(uid)
                return {'status': 'ERROR', 'message': 'Could not authenticate'}

            cipher_public_key, tag = base64.b64decode(data.get('public_key')), base64.b64decode(data.get('tag'))

            public_key = self.cryptographic_service.decrypt_and_verify_public_key(cipher_public_key, tag, response)

            ttl = current_time(365)  # TTL = 1year
            addition_status, public_key_id = self.database_service.add_public_key(username, public_key, ttl)
            if not addition_status:
                self.cache.clear_cache_by_uid(uid)
                return {'status': 'ERROR', 'message': 'Error saving the public key in IDP'}

            protocol_data = {
                'ttl': ttl,
                'public_key_id': public_key_id,
                'garbage': base64.b64encode(os.urandom(8)).decode()
            }
            cipher_data, cipher_tag = encrypt_request_data(protocol_data, secret)

            return {'status': 'OK', 'cipher_data': cipher_data, 'cipher_tag': cipher_tag}
        except Exception as e:
            self.cache.clear_cache_by_uid(uid)
            return {'status': 'ERROR', 'message': str(e)}

    @cherrypy.expose
    def generate_key(self, req_id):
        uid = rndstr(64)
        self.cache.uid2key[uid] = req_id

        secret = os.urandom(64)
        self.cache.uid2secret[uid] = secret

        secret_encoded = base64.urlsafe_b64encode(secret).decode()
        raise cherrypy.HTTPRedirect(f'{self.helper_url}?uid={uid}&secret={secret_encoded}', 303)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def handle_identity_request(self, message, tag, uid):
        try:
            secret = self.cache.uid2secret[uid]
            data = decrypt_request_data(message, tag, secret)

            status = data.pop('status', None)
            public_key_id = data.get('public_key_id')
            public_key = self.database_service.get_public_key(public_key_id, as_dict=True)

            if status == 'ATTRIBUTES_REQUEST':
                username = data.get('username')

                # Map between uid and username for further requests
                self.cache.uid2user[uid] = username
                self.cache.user2uid[username] = uid

                public_key_content = public_key.get('public_key_content')
                public_key_ttl = public_key.get('public_key_ttl')

                if public_key_content is None:
                    self.cache.clear_cache_by_uid(uid)
                    return {'status': 'ERROR', 'message': f'No public key for this account in IDP'}

                if not is_ttl_valid(public_key_ttl):
                    for _ in range(1000):  # Retry deleting if some error occurs due to concurrent accesses
                        if self.database_service.delete_public_key(public_key_id):
                            break
                    self.cache.clear_cache_by_uid(uid)
                    return {'status': 'TTL_EXCEEDED',
                            'message': 'Asymmetric keys invalid due to exceeded value of ttl'}

                attributes_signature = base64.b64decode(data.get('attributes_signature'))
                attributes = data.get('attributes', [])
                signature_status = self.cryptographic_service.verify_signature_with_public_key(public_key_content,
                                                                                               base64.b64encode(
                                                                                                   json.dumps(
                                                                                                       attributes).encode()),
                                                                                               attributes_signature)
                if not signature_status:
                    return {'status': 'ERROR', 'message': 'Invalid signature'}

                user = self.database_service.get_user(username, as_dict=True)

                if not user:
                    return {'status': 'ERROR'}

                w_u = {
                    'email': user.get('email', ''),
                    'password': base64.b64encode(user.get('password', b'')).decode()
                }
                hashed_attr = hash_password(json.dumps(w_u).encode())

                intended_attributes = {}
                for attr in attributes:
                    if attr in ['password']:
                        continue
                    val = user.get(attr)
                    if val is None:
                        continue
                    intended_attributes[attr] = val

                p_secret = os.urandom(64)
                p_secret_cipher = self.cryptographic_service.encrypt_with_public_key(public_key_content, p_secret)
                attributes_signature = self.cryptographic_service.sign_with_private_key(
                    self.cryptographic_service.private_key, json.dumps(intended_attributes).encode())
                info_attributes = {
                    'attributes': intended_attributes,
                    'signature': attributes_signature,
                    'h_attr': base64.b64encode(hashed_attr).decode()
                }
                cipher_attributes, cipher_tag = encrypt_request_data(info_attributes, p_secret)

                protocol_data = {
                    'secret': p_secret_cipher,
                    'attributes': cipher_attributes,
                    'attributes_tag': cipher_tag,
                    'garbage': base64.b64encode(os.urandom(8)).decode()
                }
                cipher_data, cipher_tag = encrypt_request_data(protocol_data, secret)
                request_data = {
                    'cipher_data': cipher_data,
                    'cipher_tag': cipher_tag,
                    'status': 'OK'
                }

                return {'status': 'OK', 'data': request_data}
        except Exception as e:
            print(e)
            return {'status': 'ERROR', 'message': str(e)}


cherrypy.config.update({
    'server.socket_host': '0.0.0.0',
    'server.socket_port': 8082,
    'server.thread_pool': 20,
    'tools.sessions.on': True,
    'tools.sessions.storage_type': "File",
    'tools.sessions.storage_path': 'idp/sessions',
    'tools.sessions.timeout': 60,
    'tools.sessions.clean_freq': 10,
    'tools.sessions.name': 'idp_session_id',
})
cherrypy.quickstart(IdP())
