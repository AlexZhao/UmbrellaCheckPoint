# UmbrellaCheckPoint     

[English](README.md) | 简体中文    

binutils:    
修改链接器，对生成的ELF文件添加PT_SIGN Program Header    
elfsign工具，对有PT_SIGN的ELF进行数字签名    

glibc patch:    
对glibc进行修改，可以在加载动态库时校验动态库中的PT_SIGN, .signature section中保存的数字签名    

linux patch:    
在加载ELF时，对PT_SIGN进行签名校验    
glibc在动态链接时校验数字签名失效，使用Linux接口内核停止该ELF的运行     

go patch:   
修改go的链接器添加 PT_SIGN 字段    

yocto patch:   
添加bblcass对整个yocto编包进行数字签名      


# 内核参数配置     

elf_sign_pub=/etc/elf_sign.der elf_sign_effect=0/1/2/3    

elf_sign_pub:  
指定公钥在磁盘的路径， 公钥格式为 x509v1, RSA2048, SHA256   

elf_sign_effect:    
0 数字签名校验实效不处理    
1 内核加载ELF校验实效停止ELF运行    
2 动态链接器校验ELF签名实效停止ELF运行    
3 使用security hook实现自定义逻辑       


# 生成签名     
 1. openssl genrsa -out sign_key.key 2048                                    # Generate RSA private key    
 2. openssl req -new -x509v1 -days 4096 -key sign_key.key -out elf_sign.crt  # use x509v1 format of certification with DER encoded     
 3. openssl x509 -in elf_sign.crt -outform der -out elf_sign.der             # convert public key to DER format     

