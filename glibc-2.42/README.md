# GLIBC 2.42 PT-SIGN functionalities

use public key file /etc/elf_sign.der as default

glibc new tunables glibc.rtld.verify_cert: /etc/elf_sign.der   

the public key need to store as x509 certificate 

PKCS1, Sha256 Digest, with RSA 2046bits public key

full linux bootup verified 


