from helper.managers import CacheManager, ZKPManager, DatabaseManager, CryptographicManager, DispatcherManager
from utils import hash_password, static_page, error_page, is_ttl_valid, scrypt_password, encrypt_request_data, \
    decrypt_request_data, show_blank_page_on_error
from jinja2 import Environment, FileSystemLoader
from biometric_systems.facial import facial_recognition
import functools
import cherrypy
import requests
import base64
import os
import json


@cherrypy.config(**{'request.error_response': functools.partial(show_blank_page_on_error, cherrypy)})
class Application:
    def __init__(self):
        self.jinja_env = Environment(loader=FileSystemLoader('static'))
        self.cache = CacheManager()
        self.zkp_service = ZKPManager()
        self.database_service = DatabaseManager('helper/helper.db', 'helper/tables.sql')
        self.cryptographic_service = CryptographicManager()
        self.idp_url = 'http://localhost:8082'
        self.dispatcher = DispatcherManager(self.idp_url)
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

    """
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
    """

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
                        return self.dispatcher.zkp_authentication(self.zkp_service, secret, username, password, uid,
                                                                  account_id, master_password)
                    return page
                else:
                    return self.dispatcher.zkp_authentication(self.zkp_service, secret, username, password, uid,
                                                              account_id, master_password)

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
        facial_recognition.recognition()


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
