from socket import gethostbyname
from random import choice
import string

from django.http import HttpResponse


def get_fail_response(wait=3):
    response = HttpResponse()
    response['Auth-Status'] = "Invalid login or password"
    response['Auth-Wait'] = wait
    return response


def get_success_response(user, address, port, password=None):
    response = HttpResponse()
    response['Auth-Status'] = 'OK'
    response['Auth-Server'] = gethostbyname(address)
    response['Auth-Port'] = port
    response['Auth-User'] = user
    if password is not None: response['Auth-Pass'] = password
    return response


def generate_password(length=20, chars=string.letters + string.digits):
    return ''.join([choice(chars) for i in range(length)])