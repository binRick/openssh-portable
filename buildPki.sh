#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
origDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EASYRSA="/usr/share/easy-rsa/3.0.6/easyrsa"
INTERFACE="$(route -n| grep ^0.0.0.0|tr -s ' '|cut -d' ' -f8|grep '^[a-z].*[0-9]$'|head -n1)"
IP="$(ifconfig $INTERFACE | grep inet| tr -s ' '| cut -d' ' -f3|grep '^[0-9].*[0-9]$'|head -n1)"

if [ ! -x "$EASYRSA" ]; then
  wget -4 --no-check-certificate https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v3.0.6.tgz
  tar zxvf EasyRSA-unix-v3.0.6.tgz
  rm -rf /usr/share/easy-rsa
  mkdir -p /usr/share/easy-rsa
  mv EasyRSA-v3.0.6 /usr/share/easy-rsa/3.0.6
fi


if [ ! -x "$EASYRSA" ]; then
	echo "easy-rsa required ($EASYRSA)"
	exit 1
fi

rm -rf pki

$EASYRSA \
	init-pki

$EASYRSA \
	--req-cn="$(hostname -f)" \
	--subject-alt-name="DNS:$(hostname -f),IP:$IP" \
	--batch \
	build-ca nopass

$EASYRSA \
	--batch --req-cn="$(hostname -f)" \
	--subject-alt-name="DNS:$(hostname -f),IP:$IP" \
	--batch \
	build-server-full server nopass

$EASYRSA \
	--batch \
	gen-crl


cat pki/private/server.key pki/issued/server.crt > server.pem
openssl rsa -in server.pem -pubout -out pki/issued/server.pub
rm server.pem

ls -al \
	pki/issued/server.crt \
	pki/issued/server.pub \
	pki/private/server.key \
	pki/private/ca.key \
	pki/crl.pem


 



