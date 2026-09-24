#!/bin/bash
# Generate development mTLS certificates for testing
# DO NOT USE IN PRODUCTION

set -e

CERTS_DIR="certs"
mkdir -p $CERTS_DIR

echo "==> Generating CA certificate..."
openssl req -new -x509 -days 3650 -nodes \
  -out $CERTS_DIR/ca.crt \
  -keyout $CERTS_DIR/ca.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Dev/CN=Synthaea Dev CA"

echo "==> Generating server certificate..."
openssl req -new -nodes \
  -out $CERTS_DIR/server.csr \
  -keyout $CERTS_DIR/server.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Dev/CN=localhost"

openssl x509 -req -days 3650 \
  -in $CERTS_DIR/server.csr \
  -CA $CERTS_DIR/ca.crt \
  -CAkey $CERTS_DIR/ca.key \
  -CAcreateserial \
  -out $CERTS_DIR/server.crt

echo "==> Generating test agent certificate..."
openssl req -new -nodes \
  -out $CERTS_DIR/agent-test.csr \
  -keyout $CERTS_DIR/agent-test.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Agents/CN=agent-test-001"

openssl x509 -req -days 3650 \
  -in $CERTS_DIR/agent-test.csr \
  -CA $CERTS_DIR/ca.crt \
  -CAkey $CERTS_DIR/ca.key \
  -CAcreateserial \
  -out $CERTS_DIR/agent-test.crt

rm $CERTS_DIR/*.csr

echo "==> Certificates generated in $CERTS_DIR/"
echo "    ca.crt/key - CA certificate and key"
echo "    server.crt/key - Server certificate for nginx"
echo "    agent-test.crt/key - Test agent client certificate"
