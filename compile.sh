#!/bin/bash
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
origDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
set -e

#sudo yum -y install openssl-devel jansson-devel mariadb-server

#  LIBJWT
#if [ ! -e "libjwt.a" ]; then
if [ ! -e libjwt.so.0 ]; then
    JWTPATH=~/.libjwt
    rm -rf $JWTPATH
    git clone ssh://git@github.com/benmcollins/libjwt $JWTPATH
    cd $JWTPATH
    autoreconf -vi
    ./configure
    make
    if [ -e libjwt.so ]; then unlink libjwt.so; fi
    if [ -e libjwt.so.0 ]; then unlink libjwt.so.0; fi

    #cp ~/.libjwt/libjwt/.libs/libjwt.a $origDir/.
    #cp ./libjwt/.libs/libjwt.a $origDir/.
    cp ./libjwt/.libs/libjwt.so $origDir/.
    cp ./libjwt/.libs/libjwt.so.0 $origDir/.
    cp ./include/jwt.h $origDir/.
    #ar -rc libjwt.a libjwt.so
    #rm libjwt.so 
    #rm libjwt.so.0

    cd $origDir
fi

if [ ! -e configure ]; then
    autoreconf -i
fi
if [ ! -e Makefile ]; then
    ./configure
fi

grep '^LIBS=' Makefile| grep 'ljwt' || sed -i 's/^LIBS=/LIBS=-ljwt /g' Makefile
grep '^CPPFLAGS=' Makefile | grep $JWTPATH || replace 'CPPFLAGS=' "CPPFLAGS=-I${JWTPATH}/include " -- Makefile

make

ls -al ssh-agent
ldd ssh-agent


set +e
rm -rf test_socket
set -e


coproc sshAddProc { LD_LIBRARY_PATH=. exec ./ssh-agent -dsa test_socket; }
echo Spawned PID $sshAddProc_PID


sleep .5


if [ -e test_key ]; then unlink test_key; fi
if [ -e test_key.pub ]; then unlink test_key.pub; fi

ssh-keygen -t rsa -N "" -f test_key
ls -al test_key*

set +e
SSH_AUTH_SOCK=test_socket ssh-add -l >/dev/null 2>&1
SSH_AUTH_SOCK=test_socket ssh-add test_key >/dev/null 2>&1
SSH_AUTH_SOCK=test_socket ssh-add -l 2>/dev/null | grep test_key

kill $sshAddProc_PID
rm -rf test_socket
set -e


openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"
openssl x509 -pubkey -in cert.pem -noout > pub.key
ls -al key.pem cert.pem pub.key

coproc sshAddProc { LD_LIBRARY_PATH=. \
    ISSUER="$(echo -n web1.$(hostname -d)|base64 -w 0)" \
    PUBLIC_KEY="$(cat pub.key|base64 -w0)" \
    exec ./ssh-agent -dsa test_socket; }

echo Spawned PID $sshAddProc_PID
set +e
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add -l
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add test_key
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add -l

kill $sshAddProc_PID
rm -rf test_socket


coproc sshAddProc { LD_LIBRARY_PATH=. \
    ISSUER="$(echo -n web1.$(hostname -d)|base64 -w 0)" \
    PUBLIC_KEY="$(cat ~/PUBLIC_KEY.txt|base64 -w0)" \
    exec ./ssh-agent -dsa test_socket; }

echo Spawned PID $sshAddProc_PID
set +e
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add -l
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add test_key
$AUTH_TOKEN="$(cat ~/validToken.txt)" SSH_AUTH_SOCK=test_socket ssh-add -l

kill $sshAddProc_PID
rm -rf test_socket


#set +e
#if [ -e test_socket ]; then unlink test_socket; fi
#set -e

echo -e "\n\n"
echo OK
echo -e "\n\n"






echo Building PKI

./buildPki.sh





