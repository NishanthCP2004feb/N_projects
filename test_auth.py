import urllib.request, json

for uname in ('testuser3','testuser3'):
    pass

# Signup
url = 'http://127.0.0.1:5000/signup'
data = json.dumps({'username':'testuser3','password':'s3cret'}).encode('utf-8')
req = urllib.request.Request(url, data=data, headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print('signup', r.status, r.read().decode())
except Exception as e:
    print('signup error', e)

# Login
url2 = 'http://127.0.0.1:5000/login'
data2 = json.dumps({'username':'testuser3','password':'s3cret'}).encode('utf-8')
req2 = urllib.request.Request(url2, data=data2, headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req2, timeout=5) as r:
        print('login', r.status, r.read().decode())
except Exception as e:
    print('login error', e)
