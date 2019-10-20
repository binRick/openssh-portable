#!/bin/bash
_VENV_PATH=~/.jwtVenv
export ENCRYPTED_KEY_PASSPHRASE="12341234"
export PRIV_KEY_FILE=pki/private/server.key
export PUB_KEY_FILE=pki/issued/server.pub
set -e
if [ ! -f "$PRIV_KEY_FILE" ]; then
	./buildPki.sh
fi
if [ ! -d "$_VENV_PATH" ]; then
	python3 -m venv $_VENV_PATH;
fi
source $_VENV_PATH/bin/activate;

set +e && (./_jwtTest.py --test | grep OK) >/dev/null 2>&1 || { 
	rm -rf $_VENV_PATH;
	python3 -m venv $_VENV_PATH;
	source $_VENV_PATH/bin/activate;
	pip install python-jose pycrypto;
}

set -e

rm -rf test_socket

coproc sshAddProc { LD_LIBRARY_PATH=. \
    ISSUER="$(echo -n $(hostname -f)|base64 -w 0)" \
    PUBLIC_KEY="$(cat pki/issued/server.pub|base64 -w0)" \
    exec ./ssh-agent -Dsa test_socket; }

echo Spawned PID $sshAddProc_PID


if [ -e test_key ]; then unlink test_key; fi
if [ -e test_key.pub ]; then unlink test_key.pub; fi
if [ -e test_key_encrypted ]; then unlink test_key_encrypted; fi
if [ -e test_key_encrypted.pub ]; then unlink test_key_encrypted.pub; fi

ssh-keygen -t rsa -N "" -f test_key
ssh-keygen -t rsa -N "$ENCRYPTED_KEY_PASSPHRASE" -f test_key_encrypted
ls -al test_key*

VALID_TOKEN="$(PRIV_KEY_FILE=$PRIV_KEY_FILE PUB_KEY_FILE=$PUB_KEY_FILE ./_jwtTest.py --encode)"
echo VALID_TOKEN=$VALID_TOKEN

set +e
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add -l 2>/dev/null
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add test_key 2>/dev/null
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN passh -p "$ENCRYPTED_KEY_PASSPHRASE" -P "Enter passphrase for test_key_encrypted:" ssh-add test_key_encrypted 2>/dev/null

set -e
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add -l 2>/dev/null | grep ' test_key (RSA'
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add -l 2>/dev/null | grep ' test_key_encrypted (RSA'

kill $sshAddProc_PID

echo
echo OK- Loaded test_key and test_key_encrypted

