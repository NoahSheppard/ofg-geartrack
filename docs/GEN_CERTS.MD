# Generate Certificates

For a new instance, please keep certifiactes as they all link...

```
# IDP Signing Certificate
openssl req -x509 -newkey rsa:2048 -keyout certificates/idp-signing.key -out certificates/idp-signing.cert -days 365 -nodes -subj "/CN=geartrack-idp-signing"

# IDP Encryption Certificate
openssl req -x509 -newkey rsa:2048 -keyout certificates/idp-encrypt.key -out certificates/idp-encrypt.cert -days 365 -nodes -subj "/CN=geartrack-idp-encryption"

# SP Signing Certificate
openssl req -x509 -newkey rsa:2048 -keyout certificates/sp-signing.key -out certificates/sp-signing.cert -days 365 -nodes -subj "/CN=geartrack-sp-signing"

# SP Encryption Certificate
openssl req -x509 -newkey rsa:2048 -keyout certificates/sp-encrypt.key -out certificates/sp-encrypt.cert -days 365 -nodes -subj "/CN=geartrack-sp-encryption"
```

## Or if you prefer one command, 

`openssl req -x509 -newkey rsa:2048 -keyout certificates/idp-signing.key -out certificates/idp-signing.cert -days 365 -nodes -subj "/CN=geartrack-idp-signing" && openssl req -x509 -newkey rsa:2048 -keyout certificates/idp-encrypt.key -out certificates/idp-encrypt.cert -days 365 -nodes -subj "/CN=geartrack-idp-encryption" && openssl req -x509 -newkey rsa:2048 -keyout certificates/sp-signing.key -out certificates/sp-signing.cert -days 365 -nodes -subj "/CN=geartrack-sp-signing" && openssl req -x509 -newkey rsa:2048 -keyout certificates/sp-encrypt.key -out certificates/sp-encrypt.cert -days 365 -nodes -subj "/CN=geartrack-sp-encryption"`

## Or in script form...
`sh scripts/gen_certs.sh;`