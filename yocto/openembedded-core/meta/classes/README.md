# Yocto PT SIGN bbclass    

New Environment variables    

PT_SIGN_KEY = ""   the signing key need to put with local.conf, the private key used to sign the ELF     
ENABLE_PT_SIGN = "1/0"   enable or not       


put below under local.conf to enable ptsign globally     
INHERIT += "ptsign"

it will sign every package linked with binutils ld    



