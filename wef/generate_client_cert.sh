#!/usr/bin/env bash

# https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription#setting-up-a-source-initiated-subscription-where-the-event-sources-are-not-in-the-same-domain-as-the-event-collector-computer
# The client.pfx needs to be located in the Cert:\LocalMachine\My store of the Windows host.
# It can be imported and the permissions granted to Network Service with
# FUTURE: See if Network Service is the one who requires permission
# $cert = Import-PfxCertificate -FilePath C:\temp\client.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString -AsPlainText -Force password)
# $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
# $keyPath = [System.IO.Path]::Combine($env:ProgramData, "Microsoft", "Crypto", "Keys", $key.Key.UniqueName)
# $keyAcl = Get-Acl -LiteralPath $keyPath
# $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
#     [System.Security.Principal.SecurityIdentifier]"S-1-5-20",
#     "Read",
#     "Allow")
# $keyAcl.SetAccessRule($accessRule)
# Set-Acl -LiteralPath $keyPath $keyAcl

# # The CA also needs to be trusted.
# $ca = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('C:\temp\ca.pem')
# $store = Get-Item Cert:\LocalMachine\Root
# $store.Open('ReadWrite')
# $store.Add($ca)
# $store.Dispose()

PASSWORD="password"
SERVER_CN="/CN=jborean-laptop"
SERVER_SAN=$(cat <<EOF
DNS.1 = jborean-laptop
IP.1 = 192.168.122.1
EOF
)
CLIENT_CN="/CN=jborean-laptop"
CLIENT_SAN=$(cat <<EOF
DNS.1 = jborean-laptop
EOF
)
# subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:${CLIENT_USERNAME}@localhost

# Generate CA
echo "Generating system trusted CA issuer"
openssl genrsa \
    -aes256 \
    -out ca.key \
    -passout pass:"${PASSWORD}"

openssl req \
    -new \
    -x509 \
    -days 365 \
    -key ca.key \
    -out ca.pem \
    -subj "/CN=WEF CA" \
    -passin pass:"${PASSWORD}"

echo "Generating server cert"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
${SERVER_SAN}
EOL

openssl req \
    -new \
    -sha256 \
    -subj "${SERVER_CN}" \
    -newkey rsa:2048 \
    -keyout server.key \
    -out server.csr \
    -config openssl.conf \
    -reqexts v3_req_client \
    -passin pass:"${PASSWORD}" \
    -passout pass:"${PASSWORD}"

openssl x509 \
    -req \
    -in server.csr \
    -sha256 \
    -out server.pem \
    -days 365 \
    -extfile openssl.conf \
    -extensions v3_req_client \
    -passin pass:"${PASSWORD}" \
    -CA ca.pem \
    -CAkey ca.key \
    -CAcreateserial

openssl pkcs12 \
  -export \
  -out server.pfx \
  -inkey server.key \
  -in server.pem \
  -passin pass:"${PASSWORD}" \
  -passout pass:"${PASSWORD}"

rm openssl.conf

echo "Generating client cert"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
${CLIENT_SAN}
EOL

openssl req \
  -new \
  -sha256 \
  -subj "${CLIENT_CN}" \
  -newkey rsa:2048 \
  -keyout client2.key \
  -out client.csr \
  -config openssl.conf \
  -reqexts v3_req_client \
  -passin pass:"${PASSWORD}" \
  -passout pass:"${PASSWORD}"

openssl x509 \
  -req \
  -in client.csr \
  -sha256 \
  -out client.pem \
  -days 365 \
  -extfile openssl.conf \
  -extensions v3_req_client \
  -passin pass:"${PASSWORD}" \
  -CA ca.pem \
  -CAkey ca.key \
  -CAcreateserial

openssl pkcs12 \
  -export \
  -out client.pfx \
  -inkey client.key \
  -in client.pem \
  -passin pass:"${PASSWORD}" \
  -passout pass:"${PASSWORD}"

rm openssl.conf
