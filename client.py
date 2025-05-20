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
        return self.session.get(path, verify= False)
    
    def fetch_with_not_valid_token(self, token_type: str):
        invalid_tokens = {
            "invalid" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.pqp1vbV2uSCy7n6SrIaMWeLZg8kVXX2aq9S2WcD-dMI",
            "expired" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzQ3NzAzODY2fQ.ikpMv9dUMbBKtUacv_ukuaI4OgsqM_tBGZGUJF1YrgA",   
        }
        self.session.cookies.set('access_token', invalid_tokens[token_type])
        self.session.cookies.set("auth_algorithm", 'hmac')
        return self.fetch_api_protected()


def menu():
    print("S: stop application")
    print("0: restart HTTPS client")
    print("1R: authenticate user using RSA - PKCS signature")
    print("1H: authenticate user using HMAC")
    print("2: fetch protected data")
    print("3: fetch using problematic tokens")
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
    elif(option=="3"):
        token_type = None
        while True:
            token_type = input("Choose: I (invalid)/ E (expired): ")
            if(token_type == "I" or token_type == "E"): 
                token_type = "invalid" if token_type=="I" else "expired"
                break
        response = client.fetch_with_not_valid_token(token_type)
    else:
        print(f"Option {option} not found")
    
    if response is not None:
        print(f"Status code: {response.status_code}")
        try:
            content = response.json()
            print("Response JSON:")
            print(json.dumps(content, indent=4, ensure_ascii=False))
        except Exception:
            print("Response Text:")
            print(response.text)
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
