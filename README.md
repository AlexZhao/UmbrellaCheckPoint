# UmbrellaCheckPoint
Different patches and hacks across binutils/glibc/linux kernel 

binutils sign compiled ELF with PT_SIGN program hdr
glibc rtld verify dynamic linked .so PT_SIGN before resolve linked symbols  
linux kernel verify PT_SIGN before invoke ELF and intepret      


