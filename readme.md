

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


## Sylabus
|Wireshark|MS-DOC|
-----
|Negotiate NTLM Key| if set, requests usage of the NTLM v1 session security protocol.
|Negotiate NT only|
|


NTLMSSP_NEGOTIATE_NTLM - WS (ntlmssp.negotiatentlm)
H (1 bit): If set, requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_NTLM.



NTLMSSP_REQUEST_NON_NT_SESSION_KEY - WS (ntlmssp.requestnonntsession)
If set, requests the usage of the LMOWF. An alternate name for this field is NTLMSSP_REQUEST_NON_NT_SESSION_KEY.


 NTLMSSP_NEGOTIATE_LM_KEY - (ntlmssp.negotiatelmkey)
 if set, requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended session security signing and sealing requires support from the client and the server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.


### SMB Client NTLMv1 with SMB2
/etc/samba/smb.conf
```
[global]
   client min protocol = SMB2
   client max protocol = SMB2
   server min protocol = SMB2
   server max protocol = SMB2
   ntlm auth = ntlmv1-permitted
#   client lanman auth = yes
   client NTLMv2 auth = no
## Browsing/Identification ###
```

```
sudo smbclient \\\\192.168.1.204\\C$ -U light.local/administrator --password "admin123+" 
```

if NTLMv1 is enabled, you will be able to connect.

If NTLMv1 is disabled, you will get this error.
```
session setup failed: NT_STATUS_LOGON_FAILURE


