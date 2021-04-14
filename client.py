#!/usr/bin/env python3
'''
This script is used for testing the actual server.
'''

import requests

def login():
    # Handle the login request
    headers_login = {
        'Content-type': 'application/json',
            }
    data_login = '{"username": "nome utente", "password": "xyzSafePassw0rd"}'
    url_login = 'http://localhost:8000/login'

    res_login = requests.post(url_login, headers=headers_login, data=data_login);

    return res_login.text


def filter_response(res):
    # Filtering the response to take only the token
    f = res.replace('{','')
    f = f.replace('}','')
    f = f.replace('"','')
    f = f.split(":")
    headers = f[0]
    token = f[1]

    return token


def encode(token):
    headers_encode = {
        'Content-type': 'application/json',
        'Authorization': 'Bearer %s' % token,
            }
    data_encode = '{"message": "Un chiarissimo messaggio"}'
    url_encode = 'http://localhost:8000/encode'

    res_encode = requests.post(url_encode, headers=headers_encode, data=data_encode);

    return res_encode.text


login_res = login();
token = filter_response(login_res);
encode_res = encode(token);
print(login_res)
print(encode_res)
