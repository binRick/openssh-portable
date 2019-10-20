#!/bin/bash
_VENV_PATH=~/.jwtVenv
set -e
if [ ! -d "$_VENV_PATH" ]; then
	python3 -m venv $_VENV_PATH;
fi
source $_VENV_PATH/bin/activate;

set +e && ./_jwtTest.py --test | grep OK >/dev/null 2>&1 || { 
	rm -rf $_VENV_PATH;
	python3 -m venv $_VENV_PATH;
	source $_VENV_PATH/bin/activate;
	pip install python-jose pycrypto;
}

set -e
exec ./_jwtTest.py $@
