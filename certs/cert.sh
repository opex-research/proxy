mkdir certificates
rm certificates/*
echo "generate pseudo CA private key"
#openssl genrsa -out certificates/ca.key 2048
openssl ecparam -name prime256v1 -genkey -noout -out certificates/ca.key

echo "generate pseudo CA certificate signing request"
openssl req -new -sha256 -days 3650 \
        -key certificates/ca.key -out certificates/ca.csr \
        -config ./cert-conf/ca.conf

echo "generate pseudo CA certificate"
openssl x509 \
    -req \
    -days 3650 \
    -in certificates/ca.csr \
    -signkey certificates/ca.key \
    -out certificates/ca.crt

echo "generate proxy private key"
openssl ecparam -genkey -name secp384r1 \
        -out certificates/proxy.key

echo "generate proxy certificate signing request"
openssl req -new -key certificates/proxy.key \
        -out certificates/proxy.csr -config \
         ./cert-conf/proxy.conf

echo "CA sign proxy csr"
openssl x509 \
  -req \
  -days 3650 \
  -CA certificates/ca.crt \
  -CAkey certificates/ca.key \
  -CAcreateserial \
  -in certificates/proxy.csr \
  -out certificates/proxy.pem\
  -extensions req_ext \
  -extfile cert-conf/proxy.conf

