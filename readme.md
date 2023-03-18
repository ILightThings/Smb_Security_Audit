

## Minumum Viable Product

Detect when NetNTLMv1 is supported

## TODO

Server Info
SMB signing enabled
Is Signing Required

## Output Idea

```
# Server Info
IP Address:     192.168.1.1

DNS Name:       computer
DNS Domain:     domain.com

NetBios Name:   computer
NetBios Domain: DOMAIN

# SMB Security 

[+] Signing Supported:      True
[-] Signing Required:       False

## SMB Security Dialects Supported

[+] SMBv1:                  False
[+] SMBv2:                  True
[+] SMBv3:                  True

## NTLMSSP Support

[-] NetNTLMv1:              True
```
