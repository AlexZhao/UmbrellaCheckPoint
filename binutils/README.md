# Basic PoC of elfsign within binutils 
  elfsign will modify the ELF binaries to add program hdr PT_SIGN     
  it will read ELF elfhdr and digest the contents with SHA256 and sign    
  the contents with configured RSA private key   


