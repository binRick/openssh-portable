#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
origDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EASYRSA="/usr/share/easy-rsa/3.0.6/easyrsa"
INTERFACE="$(route -n| grep ^0.0.0.0|tr -s ' '|cut -d' ' -f8|grep '^[a-z].*[0-9]$')"
IP="$(ifconfig $INTERFACE | grep inet| tr -s ' '| cut -d' ' -f3|grep '^[0-9].*[0-9]$')"


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


ls -al \
	pki/issued/server.crt \
	pki/private/server.key \
	pki/private/ca.key \
	pki/crl.pem


 



