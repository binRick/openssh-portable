#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

OPTS="-ljwt"

gcc -c -fPIC lib_rick.c -o lib_rick.o
ar rcs lib_rick.a lib_rick.o
#gcc rick.c -o rick -L. -l_rick -ljwt
gcc rick.c  -L. -L./openssl-1.0.2t -ljwt  -lcrypto -lssl -ljansson -ldl -l_rick -o rick



# -ljwt

