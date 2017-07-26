#!/usr/bin/python
import requests 
import base64
import hashlib
import hmac
import time
from datetime import datetime

BASE_URL = "https://api.threatconnect.com"

__url__ = BASE_URL

requestType = "GET"
def query(uri):
    timestamp = int(time.time())
    signature = "{0}:{1}:{2}".format(uri,requestType,timestamp)

    hmac_signature = hmac.new(TC_SECRET_KEY.encode(), signature.encode(), digestmod=hashlib.sha256).digest()
    authorization = 'TC {0}:{1}'.format(TC_API_ID, base64.b64encode(hmac_signature).decode())

    headers = {"Timestamp" : str(timestamp), "Authorization" : authorization}

    r = requests.get(BASE_URL + uri,headers=headers)

    return r.json()
    

def fetch():

    allData=[];
    
    uri = "/v2/tags/asdf/indicators/?resultStart=&resultLimit=50"

    json = query(uri)
    allData += json["data"]["indicator"]
    total = int(json["data"]["resultCount"])

    #pagination
    for i in range(50,total,50):
        uri = "/v2/tags/asdf/indicators/?resultStart={}&resultLimit=50".format(i);
        json = query(uri)
        allData += json["data"]["indicator"]
        
    output = {}
    
    for record in allData:
        if record["type"] == "Host" or record["type"] == "Address":
            output[record["summary"]] = ("asdf, Added: {}".format(record["dateAdded"]),record["webLink"])

    return output
