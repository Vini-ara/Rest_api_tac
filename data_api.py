from http.server import BaseHTTPRequestHandler, HTTPServer
from dotenv import load_dotenv
import datetime
import os
import json
import jwt
import sqlite3
import bcrypt

load_dotenv()

class MyHandler(BaseHTTPRequestHandler):
    def load_acces_token(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookies = {key.strip(): value.strip() for key, value in 
                       (item.split('=') for item in cookie_header.split(';'))}
            access_token = cookies.get('access_token')
            return access_token
    
    def validate_access_token(self, token):
        try:
            decoded_token = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
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
           

    def do_GET(self):
        access_token = self.load_acces_token()
        if(access_token is None):
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"Unauthorized": "Access token not found"}')

        if(self.validate_access_token(access_token)):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"message": "Hello, World!"}')

    
def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

run(handler_class=MyHandler)
