import os
from pathlib import Path
import cherrypy
import base64
import hashlib
import json
from saml2.s_utils import rndstr
from cherrypy.lib.static import serve_file
from utils import random_name, read_public_key, rsa_public_key_verify_signature, error_page


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


# @cherrypy.config(**{'request.error_response': show_blank_page_on_error})
class SP(object):
    def __init__(self):
        self.account_dir = 'sp/accounts'
        self.helper_url = 'http://localhost:8083'
        self.config_path = 'sp/sp_conf.json'
        with open('pki_idp/cert.pem', 'rb') as f:
            self.idp_public_key = read_public_key(f.read())

    def verify_idp_signature(self, content, signature):
        signature = base64.b64decode(signature)
        try:
            return rsa_public_key_verify_signature(self.idp_public_key, content, signature)
        except:
            return False

    def get_account(self):
        user_id = cherrypy.session.get('user_id')

        if user_id is None:
            raise cherrypy.HTTPRedirect('/', status=307)

        return base64.b64encode(user_id.encode()).decode()

    # Present the account images and an upload form
    def account_contents(self, account):
        contents = f'<html><body><h1>Account = {cherrypy.session.get("email")}</h1>'
        contents += f'<a href="/logout">Logout</a>'
        contents += '<p>Upload a new image file</p>'
        contents += '<form action="add" method="post" enctype="multipart/form-data">'
        contents += '<input type="file" name="image" /><br>'
        contents += '<input type="submit" value="send" />'
        contents += '</form>'
        contents += '<form action="add" method="post" enctype="multipart/form-data">'
        contents += '<p>List of uploaded image file</sp>'
        contents += '<table border=0><tr>'

        path = f'{self.account_dir}/{account}'
        files = os.listdir(path)
        count = 0
        for f in files:
            contents += '<td><img src="/img?name=' + f + '"></td>'
            count += 1
            if count % 4 == 0:
                contents += '</tr><tr>'
        contents += '</tr></body></html>'
        return contents

    # Root HTTP server method
    @cherrypy.expose
    def index(self):
        user_id = cherrypy.session.get('user_id')
        if user_id is None:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            query = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
            url_with_query = f'{self.helper_url}/sp_identity_request?query={query}&req_id={rndstr(64)}'
            raise cherrypy.HTTPRedirect(url_with_query, 303)

        account = self.get_account()
        path = f'{self.account_dir}/{account}'
        Path(path).mkdir(parents=True, exist_ok=True)

        raise cherrypy.HTTPRedirect('/account', status=307)

    @cherrypy.expose
    def account(self):
        account = self.get_account()
        return self.account_contents(account)

    @cherrypy.expose
    def img(self, name):
        account = self.get_account()
        path = os.getcwd() + f'/{self.account_dir}/{account}' + "/" + name
        return cherrypy.lib.static.serve_file(path, content_type='jpg')

    # Upload new image for an account
    @cherrypy.expose
    def add(self, image):
        name = random_name()
        account = self.get_account()

        path = Path(os.getcwd() + f'/{self.account_dir}/{account}' + "/" + name)
        m = hashlib.sha1()
        with path.open('wb') as new_file:
            while True:
                data = image.file.read(8192)
                if not data:
                    break
                new_file.write(data)
                m.update(data)

        name = base64.urlsafe_b64encode(m.digest()[0:18]).decode('utf8')
        new_path = Path(os.getcwd() + f'/{self.account_dir}/{account}' + "/" + name)
        if not new_path.exists():
            path.rename(new_path)
        else:
            path.unlink(missing_ok=True)

        return self.account_contents(account)

    # Identity provisioning by an IdP
    @cherrypy.expose
    def receive_identity_attributes(self, query):
        data = json.loads(base64.urlsafe_b64decode(query.encode()))
        attributes, signature = data.get('attributes', {}), data.get('signature', None)
        signature_status = self.verify_idp_signature(json.dumps(attributes).encode(), signature.encode())
        if not signature_status:
            return error_page('Invalid signature. Discarding received info')

        cherrypy.session['email'] = attributes.get('email')
        cherrypy.session['user_id'] = str(attributes.get('id'))
        raise cherrypy.HTTPRedirect('/', 303)

    @cherrypy.expose
    def logout(self):
        cherrypy.session.clear()
        return 'LOGOUT'


server_config = {
    'server.socket_host': '0.0.0.0',
    'server.socket_port': 8081,
    'tools.sessions.on': True,
    'tools.sessions.storage_type': "File",
    'tools.sessions.storage_path': 'sp/sessions',
    'tools.sessions.timeout': 60,
    'tools.sessions.clean_freq': 10,
    'tools.sessions.name': 'sp_session_id'
}

cherrypy.config.update(server_config)
cherrypy.quickstart(SP())
