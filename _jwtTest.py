#!/usr/bin/env python3
import sys, json, time, sys, os
from jose import jwt

if len(sys.argv) > 1 and sys.argv[1] == '--test':
	print("OK")
	sys.exit(0)

if not 'PRIV_KEY_FILE' in os.environ.keys():
	print("PRIV_KEY_FILE not found in env")
	sys.exit(1)

PRIV_KEY_FILE = os.environ['PRIV_KEY_FILE']


def getTimestampMilliseconds():
    return int(time.time() * 1000)

def getTimestamp():
    return int(time.time())


with open(PRIV_KEY_FILE,'r') as f:
	TOKEN_PRIV_KEY = f.read()

TOKEN_ALGO = 'RS256'
TOKEN_HEADERS = {
  "iat": getTimestamp(),
  "jti": 12345,
}
TOKEN_DATA = {
 "abc": 123,
}
token = jwt.encode(TOKEN_DATA, key=TOKEN_PRIV_KEY, algorithm=TOKEN_ALGO, headers=TOKEN_HEADERS)
print("{}".format(token))


