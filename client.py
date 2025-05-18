from requests import Session, Response
import requests
import json
from os import system
import urllib3

class Client():
    def __init__(self, api_url: str) -> None:
        self.api_url: str = api_url
        self.session = requests.Session()


    def authenticate_user(self, user: str, password: str, algorithm: str) -> None:
        path = f"{self.api_url}/auth/{algorithm}"
        body = {
            "username": user,
            "password": password
        }

        response = self.session.post(path, data= json.dumps(body), verify= False)    
        access_token = response.json().get('access_token')
        self.session.cookies.set("access_token", access_token)
        self.session.cookies.set("auth_algorithm", algorithm)

        return response
    
    def fetch_api_protected(self):
        path = f"{self.api_url}/data"
        return self.session.get(path, verify=False)

def menu():
    print("S: stop application")
    print("0: restart HTTP client")
    print("1R: authenticate user using RSA - PKCS signature")
    print("1H: authenticate user using HMAC")
    print("2: fetch protected data")
    print()
    print("Type command to be done")

def do_command(option, client: Client):
    response = None
    if(option=="1R"):
        response = client.authenticate_user("admin", "admin", "rsa")
    elif(option=="1H"):
        response = client.authenticate_user("admin", "admin", "hmac")
    elif(option=="2"):
        response = client.fetch_api_protected()
    else:
        print(f"Option {option} not found")
    
    if(response is not None): print(response)
    input("Type Y to continue\n")


if __name__ == "__main__":
    client = Client("https://localhost:8000")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    while(True):
        system("clear")        
        menu()
        option = input()

        if(option=="S"):
            break
        if(option=="0"):
            client = Client("https://localhost:8000")
            continue
        system("clear")        
        do_command(option, client)
