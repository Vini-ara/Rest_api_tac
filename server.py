from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import json
import jwt
import sqlite3
import bcrypt
import time
import ssl

def load_keys():
    with open("keys/hmac_secret.key", "rb") as f:
        hmac_key =  f.read().strip()
    with open("keys/rsa_public_key.pem", "rb") as f:
        public_key = f.read()
    with open("keys/rsa_private_key.pem", "rb") as f:
        private_key = f.read()

    return {
        "hmac_key": hmac_key,
        "rsa_public_key": public_key,
        "rsa_private_key": private_key
    }

db_connection = sqlite3.connect('app.db')
db_cursor = db_connection.cursor()

def db_seed():
    password = bcrypt.hashpw('admin'.encode('UTF-8'), bcrypt.gensalt())

    db_cursor.execute('''
        INSERT INTO users (username, password)
        VALUES (?, ?)
    ''', ('admin', password))
    db_connection.commit()

def config_db():
    db_cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    db_connection.commit()

class DtoValidators:
    @staticmethod
    def validateAuthentication(post_data_obj):
        if (post_data_obj.get('username', None) is None or
            post_data_obj.get('password', None) is None):
            return False
        return True


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if(self.path == ''):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"message": "Hello, World!"}')
        elif(self.path == '/data'):
            access_token, algorithm = self.load_acces_token_and_algorithm()
            if(access_token is None):
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"Unauthorized": "Access token not found"}')

            if(self.validate_access_token(access_token, algorithm)):
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Hello, World!"}')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Received POST data: {post_data.decode('utf-8')}")
        post_data_obj = json.loads(post_data.decode('utf-8'))

        if self.path == '/auth/hmac':
            if (not DtoValidators.validateAuthentication(post_data_obj)):
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Missing username or password"}')
                return

            user = db_cursor.execute("SELECT * FROM users WHERE username = ?", (post_data_obj.get('username'),)).fetchone()
        
            if user is None:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Authentication failed"}')
                return
            
            password = post_data_obj.get('password');

            print(f"UserRow: {user}")
            print(f"Pass: {password}")

            if not bcrypt.checkpw(password.encode('UTF-8'), user[2]):
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Authentication failed"}')
                return

            jwt_payload = {
                    'username': post_data_obj.get('username'),
                    'exp': int(time.time()) + 1 * 60 * 60,
                }
            hmac_secret = load_keys()['hmac_key']
            jwt_token = jwt.encode(jwt_payload, hmac_secret, algorithm='HS256')
            response = {
                'message': 'Authentication successful',
                'access_token': jwt_token
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
        
        elif self.path == '/auth/rsa':
            if (not DtoValidators.validateAuthentication(post_data_obj)):
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Missing username or password"}')
                return

            user = db_cursor.execute("SELECT * FROM users WHERE username = ?", (post_data_obj.get('username'),)).fetchone()
        
            if user is None:
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Authentication failed"}')
                return
            
            password = post_data_obj.get('password');

            print(f"UserRow: {user}")
            print(f"Pass: {password}")

            if not bcrypt.checkpw(password.encode('UTF-8'), user[2]):
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"message": "Authentication failed"}')
                return

            jwt_payload = {
                    'username': post_data_obj.get('username'),
                    'exp': int(time.time()) + 1 * 60 * 60,
                }
            
            keys = load_keys()
            private_key = keys["rsa_private_key"]
            jwt_token = jwt.encode(jwt_payload, private_key, algorithm='RS256')

            response = {
                'message': 'Authentication successful',
                'access_token': jwt_token
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))        


    def load_acces_token_and_algorithm(self):
        cookie_header = self.headers.get('Cookie')
        access_token, algorithm = None, None
        if cookie_header:
            cookies = {key.strip(): value.strip() for key, value in 
                       (item.split('=') for item in cookie_header.split(';'))}
            access_token = cookies.get('access_token')
            algorithm = cookies.get("auth_algorithm")
        return (access_token, algorithm)
    
    def validate_access_token(self, token, algorithm):
        if (algorithm == "hmac"):
            return self.validate_hmac_access_token(token)
        elif(algorithm == "rsa"):
            return self.validate_rsa_access_token(token)

    def validate_hmac_access_token(self, token):
        secret = load_keys()["hmac_key"]
        try:
            decoded_token = jwt.decode(token, secret, algorithms=["HS256"])
            return decoded_token  
        except jwt.ExpiredSignatureError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"Unauthorized": "Token expired"}')
        except jwt.InvalidTokenError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"Unauthorized": "Token Invalid"}')

    
    def validate_rsa_access_token(self, token):
        keys = load_keys()
        try:
            public_key = keys["rsa_public_key"]
            decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])
            return decoded_token
        except jwt.ExpiredSignatureError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"Unauthorized": "Token expired"}')
        except jwt.InvalidTokenError:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"Unauthorized": "Token Invalid"}')


               

    
def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='keys/cert_ssl.pem', keyfile='keys/key_ssl.pem')

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f'Starting server on port {port}...')
    httpd.serve_forever()

config_db()
run(handler_class=MyHandler)
