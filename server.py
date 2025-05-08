from http.server import BaseHTTPRequestHandler, HTTPServer
from dotenv import load_dotenv
import datetime
import os
import json
import jwt
import sqlite3
import bcrypt

load_dotenv()

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
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"message": "Hello, World!"}')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Received POST data: {post_data.decode('utf-8')}")
        post_data_obj = json.loads(post_data.decode('utf-8'))


        if self.path == '/auth':
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
                    'exp': datetime.datetime.now() + datetime.timedelta(hours=1),
                }
            
            jwt_token = jwt.encode(jwt_payload, os.getenv("JWT_SECRET"), algorithm='HS256')

            response = {
                'message': 'Authentication successful',
                'access_token': jwt_token
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))


def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()


config_db()
run(handler_class=MyHandler)
