import os

import cherrypy
import base64
import json
import requests
import functools

from idp.managers import DatabaseManager, ZKPManager, CryptographicManager, CacheManager
from utils import hash_password, error_page, current_time, is_ttl_valid, decrypt_request_data, encrypt_request_data, \
    show_blank_page_on_error, message_unwrapper, create_inner_message, message_wrapper
from saml2.s_utils import rndstr
from jinja2 import Environment, FileSystemLoader


@cherrypy.config(**{'request.error_response': functools.partial(show_blank_page_on_error, cherrypy)})
class IdP:
    def __init__(self):
        self.database_service = DatabaseManager('idp/idp.db')
        self.zkp_service = ZKPManager()
        self.cryptographic_service = CryptographicManager()
        self.cache = CacheManager()
        self.helper_url = 'http://localhost:8083'
        self.jinja_env = Environment(loader=FileSystemLoader('static'))

    def static_contents(self, path):
        return open('static/' + path, 'r').read()

    @cherrypy.expose
    def index(self):  # DONE
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        raise cherrypy.HTTPRedirect('/account')

    @cherrypy.expose
    def login(self):  # DONE
        return self.static_contents('login_idp.html')

    @cherrypy.expose
    def authenticate(self, username_or_email, password):  # DONE
        user = self.database_service.get_user_for_login(username_or_email, password)
        if not user:
            return error_page('Wrong credentials')

        cherrypy.session['user_id'] = user.get('id')
        raise cherrypy.HTTPRedirect('/account')

    @cherrypy.expose
    def sign_up(self):  # DONE
        return self.static_contents('sign_up_idp.html')

    @cherrypy.expose
    def logout(self):  # DONE
        # Clear session
        cherrypy.session.clear()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def account(self):  # DONE
        user_id = cherrypy.session.get('user_id')
        if not user_id:
            raise cherrypy.HTTPRedirect('/login')

        user = self.database_service.get_user_by_id(user_id, as_dict=True)
        username, email, password = user.get('username'), user.get('email'), user.get('password')

        template = self.jinja_env.get_template('accounts_idp.html')
        return template.render(username=username, email=email, password=password, id=user_id)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_account(self, username, email, password):  # RETURN DONE
        account_id = self.database_service.create_user(username, email, password)

        requests.post('http://localhost:8083/save_tmp_credentials', data={
            'username': username,
            'email': email,
            'password': password,
            'idp': 'http://localhost:8082'  # TODO: Put it in a variable
        })

        if account_id is not None:
            return create_inner_message("OK", data={"account_id": account_id})
        else:
            return create_inner_message("ERROR", message="Error creating a new account")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def update_account(self, user_id, password, **kwargs):  # RETURN DONE
        saved_user = self.database_service.get_user_by_id(user_id, as_dict=True)

        if not self.database_service.get_user_for_login(saved_user.get('username'), password):
            return create_inner_message("ERROR", message="Wrong password")

        kwargs['password'] = kwargs.pop('new_password', None)

        new_args = {}
        for k, v in kwargs.items():
            if k == "password" and saved_user.get(k) == hash_password(v.encode()):
                continue
            if saved_user.get(k) == v or len(v) == 0:
                continue
            new_args[k] = v

        if len(new_args) == 0:
            return create_inner_message("NOTHING")

        update_status = self.database_service.update_user(user_id, new_args)
        if not update_status:
            return create_inner_message("ERROR", message="Error while updating credentials")

        return create_inner_message("OK")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def delete_account(self, account_id):  # RETURN DONE
        removal_status = self.database_service.delete_user(account_id)
        if not removal_status:
            return create_inner_message("ERROR", "Error deleting this account")

        return create_inner_message("OK")

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def zkp_iterations(self, data, uid):
        secret = self.cache.uid2secret.get(uid)
        if not secret:
            self.zkp_service.invalidate_user(self.cache.clear_cache_by_uid(uid))
            return message_wrapper(None, None, 'No secret key')

        data = message_unwrapper(data, secret).get('data')

        try:
            username = data.get('username')
            iterations_interval = data.get('iterations_interval')
            user = self.database_service.get_user(username, as_dict=True)
            if not user:
                self.cache.clear_cache_by_uid(uid)
                inner_message = create_inner_message('NO USER', message=f'User {username} does not exists in IDP')
                return message_wrapper(inner_message, secret)

            zpk_iterations_data = self.zkp_service.negotiate_iterations(username, user.get('password'),
                                                                        iterations_interval)
            if zpk_iterations_data.get('status') != 'OK':
                return message_wrapper(zpk_iterations_data, secret)

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

        except Exception:
            self.cache.clear_cache_by_uid(uid)
            inner_message = create_inner_message("ERROR", message="Error in iterations negotiation")
            return message_wrapper(inner_message, secret)

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
