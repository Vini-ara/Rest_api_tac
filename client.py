from requests import Session, Response
import requests
import json

class Client():
    def __init__(self, auth_api_url: str, data_api_url: str) -> None:
        self.auth_api: str = auth_api_url
        self.data_api: str = data_api_url
        self.session = requests.Session()

    def authenticate_user(self, user: str, password: str) -> None:
        path = f"{self.auth_api}/auth"
        body = {
            "username": user,
            "password": password
        }
        response = self.session.post(path, data= json.dumps(body))    
        
        return response
    
Client("http://localhost:8000", "http://localhost:8000").authenticate_user("admin", "admin")
