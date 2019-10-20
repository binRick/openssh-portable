#!/bin/bash
set -e
_VENV_PATH=~/.jwtVenv
rm -rf $_VENV_PATH
python3 -m venv $_VENV_PATH
source $_VENV_PATH/bin/activate
pip install python-jose --upgrade

exec ./_jwtTest.py
