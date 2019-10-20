#!/bin/bash
_VENV_PATH=~/.jwtVenv
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

ssh-keygen -t rsa -N "" -f test_key
ls -al test_key*

VALID_TOKEN="$(PRIV_KEY_FILE=$PRIV_KEY_FILE PUB_KEY_FILE=$PUB_KEY_FILE ./_jwtTest.py --encode)"
VALID_TOKEN="$(PRIV_KEY_FILE=pki/private/server.key PUB_KEY_FILE=pki/issued/server.pub ./_jwtTest.py --encode)"


echo VALID_TOKEN=$VALID_TOKEN

set +e

SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add -l
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add test_key

set -e
SSH_AUTH_SOCK=test_socket AUTH_TOKEN=$VALID_TOKEN ssh-add -l | grep test_key

echo
echo OK
