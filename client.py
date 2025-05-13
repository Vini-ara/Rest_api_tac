from requests import Session, Response
import requests
import json

class Client():
    def __init__(self, api_url: str) -> None:
        self.api_url: str = api_url
        self.session = requests.Session()

    def authenticate_user(self, user: str, password: str) -> None:
        path = f"{self.api_url}/auth"
        body = {
            "username": user,
            "password": password
        }
        response = self.session.post(path, data= json.dumps(body))    
        access_token = response.json().get('access_token')
        self.session.cookies.set("access_token", access_token)

        return response
    
    def fecht_api_protected(self):
        path = f"{self.api_url}/data"
        return self.session.get(path)
    
client = Client("http://localhost:8000")
client.authenticate_user("admin", "admin")
print(client.fecht_api_protected())
