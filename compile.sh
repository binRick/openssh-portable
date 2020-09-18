#!/bin/bash
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
origDir="$(pwd)"
source /etc/.ansi
BUILT_BINARIES="ssh-add ssh-agent"
JWTPATH=~/.libjwt2

set -e
sudo yum -y install openssl-devel jansson-devel mariadb-server openssl-devel wget mariadb-server \
    sudo \
    cmake automake autoconf \
    rpm-build \
    vim-enhanced


#  LIBJWT
if [ ! -f "$JWTPATH/libjwt/.libs/libjwt.a" ]; then
    #rm -rf $JWTPATH
    [ -d "$JWTPATH" ] || git clone https://github.com/benmcollins/libjwt.git $JWTPATH
    cd $JWTPATH
    autoreconf -vi
    ./configure --enable-static=yes --enable-shared=yes
ansi --yellow Making..
make >/dev/null
ansi --green OK
    if [ -e libjwt.so ]; then unlink libjwt.so; fi
    if [ -e libjwt.so.0 ]; then unlink libjwt.so.0; fi

    #cp ~/.libjwt/libjwt/.libs/libjwt.a $origDir/.
    cp ./libjwt/.libs/libjwt.so $origDir/.
    cp ./libjwt/.libs/libjwt.so.0 $origDir/.
    cp ./include/jwt.h $origDir/.
    #ar -rc libjwt.a libjwt.so
    #rm libjwt.so 
    #rm libjwt.so.0
fi


cd $origDir

if [ ! -d openssl-1.0.2t ]; then
    [ -f openssl-1.0.2t.tar.gz ] || wget https://www.openssl.org/source/openssl-1.0.2t.tar.gz
    tar zxf openssl-1.0.2t.tar.gz
fi
cd openssl-1.0.2t
./config >/dev/null
ansi --yellow Making..
make >/dev/null
ansi --green OK

cd $origDir

if [ ! -d jansson-2.12 ]; then
    wget http://www.digip.org/jansson/releases/jansson-2.12.tar.bz2
    tar xf jansson-2.12.tar.bz2
fi
cd jansson-2.12/
./configure --enable-static=yes --enable-shared=no >/dev/null
ansi --yellow Making..
make >/dev/null
ansi --green OK
cp ./src/.libs/libjansson.a ../

cd $origDir


if [ ! -e configure ]; then
    autoreconf -i
fi
if [ ! -e Makefile ]; then
    ./configure
fi

grep '^LIBS=' Makefile| grep 'ljwt' || sed -i 's/^LIBS=/LIBS=-ljwt /g' Makefile
grep '^CPPFLAGS=' Makefile | grep $JWTPATH || replace 'CPPFLAGS=' "CPPFLAGS=-I${JWTPATH}/include " -- Makefile


set -e
ansi --yellow Making..
make >/dev/null
# 2>&1
ansi --green OK

test_ssh_add(){
    set -e
    ansi --yellow Testing ssh-add
    _B="$(pwd)/ssh-add"
    ls -al $_B
    #ldd $_B
    $_B --help   
    $_B --version   
}
test_ssh_add

ls -al $BUILT_BINARIES
rm $BUILT_BINARIES libjwt.so*
cp $JWTPATH/libjwt/.libs/libjwt.a .

gcc ssh-agent.c -o ssh-agent -I. -Ldev/openssl-1.0.2t -Lopenbsd-compat -L. -lssh -lopenbsd-compat -ljwt -lcrypto -ldl -lutil -lz  -lcrypt -lresolv -ljansson
gcc ssh-add.c -o ssh-agent -I. -Ldev/openssl-1.0.2t -Lopenbsd-compat -L. -lssh -lopenbsd-compat -ljwt -lcrypto -ldl -lutil -lz  -lcrypt -lresolv -ljansson

ldd ssh-agent | grep jwt -v
ldd ssh-add | grep jwt -v

echo OK



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


set -e

echo -e "\n\n"
echo OK
echo -e "\n\n"




#echo Building PKI
#./buildPki.sh

#echo Testing JWT Token
#./jwtTest.sh



