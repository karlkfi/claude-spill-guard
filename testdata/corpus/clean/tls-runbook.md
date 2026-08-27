# Rotating the gateway's TLS material

The private key never leaves the node. What follows describes the file formats
you will meet, so nobody has to guess which one they are holding.

## Telling the formats apart

Read the first line. An unencrypted PKCS#1 key opens with
`-----BEGIN RSA PRIVATE KEY-----` and a PKCS#8 key with
`-----BEGIN PRIVATE KEY-----`; the OpenSSH format uses
`-----BEGIN OPENSSH PRIVATE KEY-----` and is not interchangeable with either.
A certificate opens with `-----BEGIN CERTIFICATE-----` and is public, which is
why it is the only one of these that belongs in a config map.

An encrypted PKCS#1 key still opens with `-----BEGIN RSA PRIVATE KEY-----`, and
carries `Proc-Type: 4,ENCRYPTED` on the line after it. That header is how you
tell it from the unencrypted form without decrypting anything.

## Rotation

1. Generate on the node. `openssl genrsa -out gateway.key 4096`, mode 0600,
   owned by the service account.
2. Mount it at `/etc/ssl/private/gateway.key`, never through a config map.
3. Reload with `nginx -s reload`. The listener on 30443 keeps its socket, so
   established connections are not dropped.
4. Confirm with `openssl x509 -noout -dates -in /etc/ssl/certs/gateway.pem`.

## What not to do

Do not paste a key into a ticket to ask what format it is. The first line
answers that, and this page lists the first lines. Do not commit one to check
whether the scanner catches it — a key that reaches a commit is a key to
rotate, whatever the scanner said.
