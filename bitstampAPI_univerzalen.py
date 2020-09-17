# 2020 03 09 izdelan skupen api ki dela za transakcije in orderje
# 2020 03 03 dodana funkcija beriTransakcije
# 2020 03 01 dodana funkcija zapisiIDzadnjeTransakcijevFile
# TODO
# zbrisem nepotrebna APIja

global loginKombinacija
import LoginPodatkiBitstampYogurt as login
#import botek
import hashlib
import hmac
import time
import requests
import uuid
import sys
import json


# def inicializacija(loginKombinacija):
# if loginKombinacija == "yogurt":
#     import LoginPodatkiBitstampYogurt as login
# elif loginKombinacija == "2percent":
#     import LoginPodatkiBitstampDanilo as login

def API(payload,url):
    timestamp = str(int(round(time.time() * 1000)))
    nonce = str(uuid.uuid4())
    content_type = 'application/x-www-form-urlencoded'
    if sys.version_info.major >= 3:
        from urllib.parse import urlencode
    else:
        from urllib import urlencode
    payload_string = urlencode(payload)
    message = 'BITSTAMP ' + login.api_key + \
        'POST' + \
        'www.bitstamp.net' + \
        url + \
        '' + \
        content_type + \
        nonce + \
        timestamp + \
        'v2' + \
        payload_string
    message = message.encode('utf-8')
    signature = hmac.new(login.API_SECRET, msg=message, digestmod=hashlib.sha256).hexdigest()
    headers = {
        'X-Auth': 'BITSTAMP ' + login.api_key,
        'X-Auth-Signature': signature,
        'X-Auth-Nonce': nonce,
        'X-Auth-Timestamp': timestamp,
        'X-Auth-Version': 'v2',
        'Content-Type': content_type
    }
    r = requests.post(
        "https://www.bitstamp.net"+url,
        headers=headers,
        data=payload_string
        )
    if not r.status_code == 200:
        print(r.status_code)
        print(r.reason)
        raise Exception('Status code not 200')

    string_to_sign = (nonce + timestamp + r.headers.get('Content-Type')).encode('utf-8') + r.content
    signature_check = hmac.new(login.API_SECRET, msg=string_to_sign, digestmod=hashlib.sha256).hexdigest()
    if not r.headers.get('X-Server-Auth-Signature') == signature_check:
        raise Exception('Signatures do not match')
    return r.content

def APIpublic(url):
    r = requests.get("https://www.bitstamp.net"+url)
#    data = r.json()
#    orderBook = json.loads(data)
###    print(json.dumps(orderBook))
    return r.content

def izpisiOrderjeAPI(nakupniPar):
    payload = {'offset': '0'}
    url="/api/v2/open_orders/" + nakupniPar + "/"
    orderji = json.loads(API(payload, url))
    orderji.sort(key=lambda s: s['price'])
    return orderji