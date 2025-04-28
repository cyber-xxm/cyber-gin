#!/bin/bash
set -e

# 创建目录
mkdir -p certs

echo "=== 1. 生成 Root CA ==="
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=CA/CN=MyRootCA"

echo "=== 2. 创建 server证书的配置文件 (SAN) ==="
cat > certs/openssl_server.cnf <<EOF
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
req_extensions      = req_ext
distinguished_name  = dn

[ dn ]
C=CN
ST=Beijing
L=Beijing
O=MyOrg
OU=Server
CN=localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
DNS.2 = hasee.local
EOF

echo "=== 3. 创建 client证书的配置文件 (SAN) ==="
cat > certs/openssl_client.cnf <<EOF
[ req ]
default_bits        = 2048
prompt              = no
default_md          = sha256
req_extensions      = req_ext
distinguished_name  = dn

[ dn ]
C=CN
ST=Beijing
L=Beijing
O=MyOrg
OU=Client
CN=client

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = client
EOF

echo "=== 4. 生成 server key/csr/crt ==="
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr -config certs/openssl_server.cnf
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 3650 -sha256 -extensions req_ext -extfile certs/openssl_server.cnf

echo "=== 5. 生成 client key/csr/crt ==="
openssl genrsa -out certs/client.key 2048
openssl req -new -key certs/client.key -out certs/client.csr -config certs/openssl_client.cnf
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 3650 -sha256 -extensions req_ext -extfile certs/openssl_client.cnf

echo "=== 6. 整理清理临时文件 ==="
rm certs/*.csr
rm certs/*.srl

echo "全部证书生成完毕！在 certs/ 目录下："
ls -l certs/
