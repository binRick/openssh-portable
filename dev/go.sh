#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set +e; ./clean.sh

set -e

./build.sh

ldd rick
ls -al rick

./rick
