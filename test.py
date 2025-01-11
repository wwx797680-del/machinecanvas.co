import ssl
from OpenSSL import crypto

# Create a self-signed certificate
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 4096)

cert = crypto.X509()
cert.set_version(2)
cert.set_serial_number(1000)

# Set subject name
subject = cert.get_subject()
subject.C = "US"
subject.ST = "California"
subject.L = "San Francisco"
subject.O = "My Company"
subject.CN = "localhost"

cert.set_issuer(subject)
cert.set_notBefore(b"20231226000000Z")
cert.set_notAfter(b"20241226000000Z")

cert.set_pubkey(key)
cert.sign(key, "sha256")

# Write the private key and certificate to files
with open("key.pem", "wb") as key_file:
    key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

with open("cert.pem", "wb") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
