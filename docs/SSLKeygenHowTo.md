## Creating Self-Signed Certificates and Keys with OpenSSL

OpenCMW support SSL/TLS data-in-transit encryption, which secures data transmitted over the network.  The server and the
clients encrypt data using the Transport Layer Security (TLS) protocol, which is a newer version of  the Secure Socket 
Layer (SSL) protocol.

For testing purposes, OpenCMW can be configured to use TLS with self-signed certificates and keys.

*N.B. Whatever method you use to generate the certificate and key files, the Common Name value used for the server and 
client certificates/keys must each differ from the Common Name value used for the CA certificate.
Otherwise, the certificate and key files will not work for servers compiled using OpenSSL.*

### Creating the Certificate Authority's Certificate and Keys
1. Generate a private key for the CA:
```bash
$ openssl genrsa 2048 > ca-key.pem
```
2. Generate the X509 certificate for the CA:
```bash
$ openssl req -new -x509 -nodes -days 365000 \
-key ca-key.pem \
-out ca-cert.pem
```

### Creating the Server's Certificate and Keys
1. Generate the private key and certificate request:
```bash
$ openssl req -newkey rsa:2048 -nodes -days 365000 \
-keyout server-key.pem \
-out server-req.pem
```
2. Generate the X509 certificate for the server:
```bash
$ openssl x509 -req -days 365000 -set_serial 01 \
-in server-req.pem \
-out server-cert.pem \
-CA ca-cert.pem \
-CAkey ca-key.pem
```

### Creating the Client's Certificate and Keys
1. Generate the private key and certificate request:
```bash
$ openssl req -newkey rsa:2048 -nodes -days 365000 \
-keyout client-key.pem \
-out client-req.pem
```
2. Generate the X509 certificate for the client:
```bash
$ openssl x509 -req -days 365000 -set_serial 01 \
-in client-req.pem \
-out client-cert.pem \
-CA ca-cert.pem \
-CAkey ca-key.pem
```

### Verifying the Certificates
1. Verify the server certificate:
```bash
$ openssl verify -CAfile ca-cert.pem ca-cert.pem server-cert.pem
```
2. Verify the client certificate:
```bash
$ openssl verify -CAfile ca-cert.pem ca-cert.pem client-cert.pem
```