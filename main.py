import ntpath
import socket

from impacket import smb, smb3, nmb, nt_errors, LOG
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smb3structs import SMB2Packet, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, GENERIC_ALL, FILE_SHARE_READ, \
    FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_ATTRIBUTE_NORMAL, \
    SMB2_IL_IMPERSONATION, SMB2_OPLOCK_LEVEL_NONE, FILE_READ_DATA , FILE_WRITE_DATA, FILE_OPEN, GENERIC_READ, GENERIC_WRITE, \
    FILE_OPEN_REPARSE_POINT, MOUNT_POINT_REPARSE_DATA_STRUCTURE, FSCTL_SET_REPARSE_POINT, SMB2_0_IOCTL_IS_FSCTL, \
    MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE, FSCTL_DELETE_REPARSE_POINT, FSCTL_SRV_ENUMERATE_SNAPSHOTS, SRV_SNAPSHOT_ARRAY, \
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, SMB2_DIALECT_311, SMB2Negotiate_Response, \
    SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED


from impacket.smbconnection import SMBConnection


class AuditTarget:

    def __init__(self,TargetIP):
        self.TargetIP = TargetIP
        self.canConnect = False
        self.SupportedSMBDilects = []
        self.SigningEnabled = False
        self.SigningRequired = False
        self.NBName = ""
        self.NBDomain = ""
        self.DNSName = ""
        self.DNSDomain = ""

    """
    Will test will all possible SMB Dialects.
    Will also get the AVID Data like NBname,Dnsdomain, what not
    """
    def negotiatie(self):
        try:
            smbconn = SMBConnection(remoteHost=self.TargetIP,remoteName=self.TargetIP)
            self.canConnect = True
            if type(smbconn._SMBConnection ) == smb3.SMB3:
                #smbconn.negotiateSession()
                #smbconn.login(user="",password="")
                flags1=smb.SMB.FLAGS1_PATHCASELESS | smb.SMB.FLAGS1_CANONICALIZED_PATHS,
                flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES # Make sure this does not contain SMB_FLAGS2_SMB_SECURITY_SIGNATURE
                negoData='\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00'

                packet = smbconn.negotiateSessionWildcard(smbconn._myName, smbconn._remoteName, smbconn._remoteHost, smbconn._sess_port,
                                                    smbconn._timeout, True, flags1=flags1, flags2=flags2, data=negoData)

                negSessionResponse=SMB2Packet(packet)
                negResp = SMB2Negotiate_Response(negSessionResponse['Data'])

                # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5?source=recommendations
                # negResp.fields['SecurityMode']
                if negResp.fields['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_ENABLED == SMB2_NEGOTIATE_SIGNING_ENABLED:
                    self.SigningEnabled = True

                if negResp.fields['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED == SMB2_NEGOTIATE_SIGNING_REQUIRED:
                    self.SigningRequired = True

            self.DNSName = smbconn.getServerDNSHostName()
            self.DNSDomain = smbconn.getServerDNSDomainName()

            self.NBDomain = smbconn.getServerDomain()
            self.NBName = smbconn.getServerName()

            #Supports SMB Signing
            # smbconnection._SignatureVerificationEnabled
            self.SigningSupported = smbconn._SMBConnection._SignatureVerificationEnabled



        except AttributeError as d:
            print("Bad Attribute")
        except Exception as e:
            print("Something failed")
            print(e)
            pass

    

def main():
    smbtarget = "192.168.1.24"

    """ try:
        smbv2_test = SMBConnection(remoteHost=smbtarget,remoteName=smbtarget)
    except nmb.NetBIOSError as e:
        print("SMB version 2 and above")
    try:
        smbv1_test = SMBConnection(remoteHost=smbtarget,remoteName=smbtarget,preferredDialect=smb.SMB_DIALECT)
        smbv1_test.negotiateSession()
    except nmb.NetBIOSError as e:
        print("SMBv1 Not enabled") """

    t = AuditTarget(smbtarget)
    t.negotiatie()
    print(t)

    


if __name__ == "__main__":
    main()


"""
smb.SMB_DIALECT
SMB2_DIALECT_002
SMB2_DIALECT_21
SMB2_DIALECT_30
SMB2_DIALECT_311

"""