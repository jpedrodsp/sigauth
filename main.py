#!/usr/bin/python3

import urllib.request, urllib.parse
import socket, argparse
import keyring, getpass

def check_internet_connection() -> bool:
    # Get an internet-available URL to check if the connection is still active
    URL = "google.com"
    try:
        socket.gethostbyname(URL)
        return True
    except socket.gaierror:
        return False

def authenticate_in_ufpi_network(user: str, passw: str):
    url = "https://login.ufpi.br:6082/php/uid.php?vsys=1&rule=0&url=http://conecta.ufpi.br"
    headers = {
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
        "pragma": "no-cache",
    }
    data = {
        "buttonClicked": "0",
        "redirect_url": "",
        "err_flag": "0",
        "inputStr": "",
        "escapeUser": "",
        "preauthid": "",
        "user": user,
        "passwd": passw,
        "ok": "Login",
    }
    data = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(req)
        if response.geturl() == url:
            print(f"Sent: CODE {response.status}: {response.reason}")
            print("User or Password combination is wrong")
            return False
        if response.status == 200:
            print(f"Sent: CODE {response.status}: {response.reason}")
            print("Authenticated")
            return True
        else:
            print(f"Sent: CODE {response.status}: {response.reason}")
            print("Maybe not authenticated")
            return False
    except urllib.error.HTTPError as e:
        print(f"Not sent: CODE {e.code}: {e.reason}")
        return False

if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("user", help="SIG user to authenticate")
    # optional password argument
    argparser.add_argument("-p", "--password", help="SIG user's password")
    # optional argument 'clear-keyring' to reset password in keyring
    argparser.add_argument('--clear-keyring', action='store_true', help="Clear password in keyring")
    args = argparser.parse_args()
    
    APP_KEYRING_NAME = "sigauth.jpedrodsp.github.com"

    # Retrieve 'user'    
    user = args.user
    if user is None:
        print("No user informed")
        exit(1)
        
    # Check if 'clear-keyring' flag is set
    if args.clear_keyring:
        keyring.delete_password(APP_KEYRING_NAME, args.user)
        print(f'Password for user "{args.user}" deleted')
        
    # Retrieve 'password' from input. If not informed, retrieve from keyring
    passw = None
    if args.password is not None:
        passw = args.password
    else:
        passw = passw = keyring.get_password(APP_KEYRING_NAME, args.user)
        
    # If password is not in keyring, ask for it
    if passw is None:
        print(f'No password found for user "{args.user}"')
        passw = getpass.getpass(prompt="Enter password: ")
        keyring.set_password(APP_KEYRING_NAME, args.user, passw)
        
    # With the user and password, try to authenticate in UFPI network
    ufpiauth = authenticate_in_ufpi_network(args.user, passw)
    isnetavailable = check_internet_connection()
    if ufpiauth and isnetavailable:
        print("Success!")
        exit(0)
    else:
        print("Failure!")
        exit(1)