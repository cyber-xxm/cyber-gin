 
# For a list of supported curves, use "apps/openssl ecparam -list_curves".
 
# Path to the openssl distribution
OPENSSL_DIR=.
# Path to the openssl program
OPENSSL_CMD=gmssl
# Option to find configuration file
OPENSSL_CNF="-config ./openssl.cnf"
# Directory where certificates are stored
CERTS_DIR=./sm2Certs
# Directory where private key files are stored
KEYS_DIR=$CERTS_DIR
# Directory where combo files (containing a certificate and corresponding
# private key together) are stored
COMBO_DIR=$CERTS_DIR
# cat command
CAT="C:/Progra~1/Git/usr/bin/cat.exe"
# rm command
RM="C:/Progra~1/Git/usr/bin/rm.exe"
# mkdir command
MKDIR="C:/Progra~1/Git/usr/bin/mkdir.exe"
# The certificate will expire these many days after the issue date.
DAYS=3650
TEST_CA_CURVE=SM2
TEST_CA_FILE=CA
TEST_CA_DN="//skip=yes/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=SORB of TASS/CN=Test CA (SM2)"
 
TEST_SERVER_CURVE=SM2
TEST_SERVER_FILE=SS
TEST_SERVER_DN="//skip=yes/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=server sign (SM2)"
 
TEST_SERVER_ENC_FILE=SE
TEST_SERVER_ENC_DN="//skip=yes/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=server enc (SM2)"
 
TEST_CLIENT_CURVE=SM2
TEST_CLIENT_FILE=CS
TEST_CLIENT_DN="//skip=yes/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=client sign (SM2)"
 
TEST_CLIENT_ENC_FILE=CE
TEST_CLIENT_ENC_DN="//skip=yes/C=CN/ST=BJ/L=HaiDian/O=Beijing JNTA Technology LTD./OU=BSRC of TASS/CN=client sign (SM2)"
 
# Generating an EC certificate involves the following main steps
# 1. Generating curve parameters (if needed)
# 2. Generating a certificate request
# 3. Signing the certificate request 
# 4. [Optional] One can combine the cert and private key into a single
#    file and also delete the certificate request
 
mkdir -p $CERTS_DIR
mkdir -p $KEYS_DIR
mkdir -p $COMBO_DIR
 
echo "Generating self-signed CA certificate (on curve $TEST_CA_CURVE)"
echo "==============================================================="
$OPENSSL_CMD ecparam -name $TEST_CA_CURVE -out $TEST_CA_CURVE.pem
 
 
# Generate a new certificate request in $TEST_CA_FILE.req.pem. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CA_CURVE.pem and the private key is saved in $TEST_CA_FILE.key.pem
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CA_DN" \
    -keyout $KEYS_DIR/$TEST_CA_FILE.key.pem \
    -newkey ec:$TEST_CA_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_CA_FILE.req.pem
 
# Sign the certificate request in $TEST_CA_FILE.req.pem using the
# private key in $TEST_CA_FILE.key.pem and include the CA extension.
# Make the certificate valid for 1500 days from the time of signing.
# The certificate is written into $TEST_CA_FILE.cert.pem
$OPENSSL_CMD x509 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CA_FILE.req.pem \
    -extfile $OPENSSL_DIR/openssl.cnf \
    -extensions v3_ca \
    -signkey $KEYS_DIR/$TEST_CA_FILE.key.pem \
    -out $CERTS_DIR/$TEST_CA_FILE.cert.pem
 
# Display the certificate
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CA_FILE.cert.pem -text
 
# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CA_FILE.cert.pem -issuer -subject \
	 > $COMBO_DIR/$TEST_CA_FILE.pem
cat  $KEYS_DIR/$TEST_CA_FILE.key.pem >> $COMBO_DIR/$TEST_CA_FILE.pem
 
# Remove the cert request file (no longer needed)
rm  $CERTS_DIR/$TEST_CA_FILE.req.pem
 
echo "GENERATING A TEST SERVER CERTIFICATE (on elliptic curve $TEST_SERVER_CURVE)"
echo "=========================================================================="
# Generate a new certificate request in $TEST_SERVER_FILE.req.pem. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_SERVER_CURVE.pem and the private key is saved in 
# $TEST_SERVER_FILE.key.pem
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_SERVER_DN" \
    -keyout $KEYS_DIR/$TEST_SERVER_FILE.key.pem \
    -newkey ec:$TEST_SERVER_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_SERVER_FILE.req.pem
 
# Sign the certificate request in $TEST_SERVER_FILE.req.pem using the
# CA certificate in $TEST_CA_FILE.cert.pem and the CA private key in
# $TEST_CA_FILE.key.pem. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_SERVER_FILE.cert.pem
$OPENSSL_CMD x509 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_SERVER_FILE.req.pem \
    -CA $CERTS_DIR/$TEST_CA_FILE.cert.pem \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key.pem \
	-extfile $OPENSSL_DIR/openssl.cnf \
	-extensions v3_req \
    -out $CERTS_DIR/$TEST_SERVER_FILE.cert.pem -CAcreateserial
 
# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_FILE.cert.pem -text
 
# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_FILE.cert.pem -issuer -subject \
	 > $COMBO_DIR/$TEST_SERVER_FILE.pem
cat  $KEYS_DIR/$TEST_SERVER_FILE.key.pem >> $COMBO_DIR/$TEST_SERVER_FILE.pem
 
# Remove the cert request file (no longer needed)
rm  $CERTS_DIR/$TEST_SERVER_FILE.req.pem
 
echo "	GENERATING A TEST SERVER ENCRYPT CERTIFICATE (on elliptic curve $TEST_SERVER_CURVE)"
echo "  ==================================================================================="
# Generate a new certificate request in $TEST_SERVER_FILE.req.pem. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_SERVER_CURVE.pem and the private key is saved in 
# $TEST_SERVER_FILE.key.pem
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_SERVER_ENC_DN" \
    -keyout $KEYS_DIR/$TEST_SERVER_ENC_FILE.key.pem \
    -newkey ec:$TEST_SERVER_CURVE.pem -new \
    -out $CERTS_DIR/$TEST_SERVER_ENC_FILE.req.pem
 
# Sign the certificate request in $TEST_SERVER_FILE.req.pem using the
# CA certificate in $TEST_CA_FILE.cert.pem and the CA private key in
# $TEST_CA_FILE.key.pem. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_SERVER_FILE.cert.pem
$OPENSSL_CMD x509 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.req.pem \
    -CA $CERTS_DIR/$TEST_CA_FILE.cert.pem \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key.pem \
	-extfile $OPENSSL_DIR/openssl.cnf \
	-extensions v3enc_req \
    -out $CERTS_DIR/$TEST_SERVER_ENC_FILE.cert.pem -CAcreateserial
 
# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.cert.pem -text
 
# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_SERVER_ENC_FILE.cert.pem -issuer -subject \
	 > $COMBO_DIR/$TEST_SERVER_ENC_FILE.pem
cat  $KEYS_DIR/$TEST_SERVER_ENC_FILE.key.pem >> $COMBO_DIR/$TEST_SERVER_ENC_FILE.pem
 
# Remove the cert request file (no longer needed)
rm  $CERTS_DIR/$TEST_SERVER_ENC_FILE.req.pem
 
 
 
echo "GENERATING A TEST CLIENT CERTIFICATE (on elliptic curve $TEST_CLIENT_CURVE)"
echo "=========================================================================="
# Generate a new certificate request in $TEST_CLIENT_FILE.req.pem. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CLIENT_CURVE.pem and the private key is saved in 
# $TEST_CLIENT_FILE.key.pem
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CLIENT_DN" \
	     -keyout $KEYS_DIR/$TEST_CLIENT_FILE.key.pem \
	     -newkey ec:$TEST_CLIENT_CURVE.pem -new \
	     -out $CERTS_DIR/$TEST_CLIENT_FILE.req.pem
 
# Sign the certificate request in $TEST_CLIENT_FILE.req.pem using the
# CA certificate in $TEST_CA_FILE.cert.pem and the CA private key in
# $TEST_CA_FILE.key.pem. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_CLIENT_FILE.cert.pem
$OPENSSL_CMD x509 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CLIENT_FILE.req.pem \
    -CA $CERTS_DIR/$TEST_CA_FILE.cert.pem \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key.pem \
	-extfile $OPENSSL_DIR/openssl.cnf \
	-extensions v3_req \
    -out $CERTS_DIR/$TEST_CLIENT_FILE.cert.pem -CAcreateserial
 
# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_FILE.cert.pem -text
 
# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_FILE.cert.pem -issuer -subject \
	 > $COMBO_DIR/$TEST_CLIENT_FILE.pem
cat  $KEYS_DIR/$TEST_CLIENT_FILE.key.pem >> $COMBO_DIR/$TEST_CLIENT_FILE.pem
 
# Remove the cert request file (no longer needed)
rm  $CERTS_DIR/$TEST_CLIENT_FILE.req.pem
 
 
echo "	GENERATING A TEST CLIENT ENCRYPT CERTIFICATE (on elliptic curve $TEST_CLIENT_CURVE)"
echo "	==================================================================================="
# Generate a new certificate request in $TEST_CLIENT_FILE.req.pem. A 
# new ecdsa (actually ECC) key pair is generated on the parameters in
# $TEST_CLIENT_CURVE.pem and the private key is saved in 
# $TEST_CLIENT_FILE.key.pem
# WARNING: By using the -nodes option, we force the private key to be 
# stored in the clear (rather than encrypted with a password).
$OPENSSL_CMD req $OPENSSL_CNF -nodes -subj "$TEST_CLIENT_ENC_DN" \
	     -keyout $KEYS_DIR/$TEST_CLIENT_ENC_FILE.key.pem \
	     -newkey ec:$TEST_CLIENT_CURVE.pem -new \
	     -out $CERTS_DIR/$TEST_CLIENT_ENC_FILE.req.pem
 
# Sign the certificate request in $TEST_CLIENT_FILE.req.pem using the
# CA certificate in $TEST_CA_FILE.cert.pem and the CA private key in
# $TEST_CA_FILE.key.pem. Since we do not have an existing serial number
# file for this CA, create one. Make the certificate valid for $DAYS days
# from the time of signing. The certificate is written into 
# $TEST_CLIENT_FILE.cert.pem
$OPENSSL_CMD x509 -req -days $DAYS \
    -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.req.pem \
    -CA $CERTS_DIR/$TEST_CA_FILE.cert.pem \
    -CAkey $KEYS_DIR/$TEST_CA_FILE.key.pem \
	-extfile $OPENSSL_DIR/openssl.cnf \
	-extensions v3enc_req \
    -out $CERTS_DIR/$TEST_CLIENT_ENC_FILE.cert.pem -CAcreateserial
 
# Display the certificate 
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.cert.pem -text
 
# Place the certificate and key in a common file
$OPENSSL_CMD x509 -in $CERTS_DIR/$TEST_CLIENT_ENC_FILE.cert.pem -issuer -subject \
	 > $COMBO_DIR/$TEST_CLIENT_ENC_FILE.pem
cat  $KEYS_DIR/$TEST_CLIENT_ENC_FILE.key.pem >> $COMBO_DIR/$TEST_CLIENT_ENC_FILE.pem
 
# Remove the cert request file (no longer needed)
rm  $CERTS_DIR/$TEST_CLIENT_ENC_FILE.req.pem
 