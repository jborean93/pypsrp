#!/bin/bash

set -e

apt-get update

. /etc/os-release

if [[ $UBUNTU_CODENAME == "xenial" ]]
then
    echo "Installing gss-ntlmssp with apt-get"
    apt-get install -y gss-ntlmssp
else
    echo "Installing gss-ntlmssp from source"
    apt-get install -y autoconf automake m4 libtool winbind libwbclient-dev gettext xsltproc libxml2-utils docbook-xml docbook-xsl make libkrb5-dev krb5-user libsasl2-modules-gssapi-mit libunistring-dev libssl-dev doxygen-gui findutils libxml2-dev libxslt1-dev pkg-config
    git clone https://github.com/simo5/gss-ntlmssp.git
    cd gss-ntlmssp
    autoreconf -f -i
    ./configure
    make
    make install
    cd ..
    mkdir -p /usr/etc/gss
    echo "ntlmssp_v1       1.3.6.1.4.1.311.2.2.10          /usr/local/lib/gssntlmssp/gssntlmssp.so" > /usr/etc/gss/mech
fi
