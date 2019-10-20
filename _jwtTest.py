#!/usr/bin/env python3
import sys, json, time, sys, os, socket
from jose import jwt

def getIssuer():
  return socket.gethostname()

def getTimestampMilliseconds():
    return int(time.time() * 1000)

def getTimestamp():
    return int(time.time())


if len(sys.argv) > 1 and sys.argv[1] == '--test':
	print("OK")
	sys.exit(0)

if not 'PRIV_KEY_FILE' in os.environ.keys():
	print("PRIV_KEY_FILE not found in env")
	sys.exit(1)
if not 'PUB_KEY_FILE' in os.environ.keys():
	print("PUB_KEY_FILE not found in env")
	sys.exit(1)

PRIV_KEY_FILE = os.environ['PRIV_KEY_FILE']
PUB_KEY_FILE = os.environ['PUB_KEY_FILE']


with open(PRIV_KEY_FILE,'r') as f:
	TOKEN_PRIV_KEY = f.read()
with open(PUB_KEY_FILE,'r') as f:
	TOKEN_PUB_KEY = f.read()

JWT_AUDIENCE = 'vpntech.net'
JWT_SUBJECT = 'vpntech'
TOKEN_ALGO = 'RS256'
TOKEN_HEADERS = {
  "iat": getTimestamp(),
  "jti": 12345,
}
TOKEN_DATA = {
 "abc": 123,
 "iss": getIssuer(),
 "exp": getTimestamp() + 3600,
 "aud": JWT_AUDIENCE,
 "sub": JWT_SUBJECT,
}

token = jwt.encode(TOKEN_DATA, key=TOKEN_PRIV_KEY, algorithm=TOKEN_ALGO, headers=TOKEN_HEADERS)
DECODED = jwt.decode(token, key=TOKEN_PUB_KEY, algorithms=TOKEN_ALGO, audience=JWT_AUDIENCE)

if len(sys.argv) > 1 and sys.argv[1] == '--encode':
	print("{}".format(token))
	sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == '--decode':
	print("DECODED:\n{}\n".format(DECODED))
