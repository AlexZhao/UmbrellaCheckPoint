# UmbrellaCheckPoint
Different patches and hacks across binutils/glibc/linux kernel 

binutils sign compiled ELF with PT_SIGN program hdr
glibc rtld verify dynamic linked .so PT_SIGN before resolve linked symbols  
linux kernel verify PT_SIGN before invoke ELF and intepret      

It doesnt process the keyring and also mount namespace yet, but it can verify all userspace
binutils linker generated ELF, only x86_64, SHA256, RSA 2048 yet.

with security policy configured, it can block all not signed ELF to direct execute on on Linux Kernel

# Kernel parameters    


elf_sign_pub=/etc/elf_sign.der elf_sign_effect=0/1/2/3

elf_sign_pub:
public key path format current only support x509v1 sha256 with RSA 2048 

elf_sign_effect:
0 not handle the ELF without signature
1 terminate ELF/Interp without signature
2 terminate the ELF linked .so without signature
3 leave the signature process to securty hook 



