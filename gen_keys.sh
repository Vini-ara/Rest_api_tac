mkdir -p keys
# chave HMAC - 32 bytes 
openssl rand -base64 32 > keys/hmac_secret.key

# chaves RSA - 2048 bits
openssl genpkey -algorithm RSA -out keys/rsa_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/rsa_private_key.pem -out keys/rsa_public_key.pem

# SSL autoassinado
openssl req -x509 -newkey rsa:2048 -keyout keys/key_ssl.pem -out keys/cert_ssl.pem -days 365 -nodes -subj "//CN=localhost"