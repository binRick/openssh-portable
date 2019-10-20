#!/usr/bin/env python3
import sys, json
from jose import jwt
token = jwt.encode({'key': 'value'}, 'secret', algorithm='HS256')
print(token)

