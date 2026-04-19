# UmbrellaCheckPoint
Different patches and hacks across binutils/glibc/linux kernel 

binutils sign compiled ELF with PT_SIGN program hdr
glibc rtld verify dynamic linked .so PT_SIGN before resolve linked symbols  
linux kernel verify PT_SIGN before invoke ELF and intepret      

It doesnt process the keyring and also mount namespace yet, but it can verify all userspace
binutils linker generated ELF, only x86_64, SHA256, RSA 2048 yet.

with security policy configured, it can block all not signed ELF to direct execute on on Linux Kernel
