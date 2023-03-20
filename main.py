import ntpath
import socket

from impacket import smb, smb3, nmb, nt_errors, LOG
from impacket.ntlm import compute_lmhash, compute_nthash, NTLMSSP_NEGOTIATE_NTLM, getNTLMSSPType1
from impacket.smb3structs import SMB2Packet, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, GENERIC_ALL, FILE_SHARE_READ, \
    FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, FILE_ATTRIBUTE_NORMAL, \
    SMB2_IL_IMPERSONATION, SMB2_OPLOCK_LEVEL_NONE, FILE_READ_DATA , FILE_WRITE_DATA, FILE_OPEN, GENERIC_READ, GENERIC_WRITE, \
    FILE_OPEN_REPARSE_POINT, MOUNT_POINT_REPARSE_DATA_STRUCTURE, FSCTL_SET_REPARSE_POINT, SMB2_0_IOCTL_IS_FSCTL, \
    MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE, FSCTL_DELETE_REPARSE_POINT, FSCTL_SRV_ENUMERATE_SNAPSHOTS, SRV_SNAPSHOT_ARRAY, \
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_READ_EA, FILE_READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE, SMB2_DIALECT_311, SMB2Negotiate_Response, \
    SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED, SMB2SessionSetup, SMB2_SESSION_SETUP
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech



from impacket.smbconnection import SMBConnection


class AuditTarget:

    def __init__(self,TargetIP):
        self.TargetIP = TargetIP
        self.canConnect = False
        self.SupportedSMBDilects = []
        self.SupportsNTLMv1 = False
        self.SupportsLanMan = False
        self.SigningEnabled = False
        self.SigningRequired = False
        self.NBName = ""
        self.NBDomain = ""
        self.DNSName = ""
        self.DNSDomain = ""
        self.NTLMSupport = True
        self._Connection = ""


    def print(self):
        print(self.__dict__)

    """
    Will test will all possible SMB Dialects.
    Will also get the AVID Data like NBname,Dnsdomain, what not
    """
    def negotiatie(self):
        try:
            smbconn = SMBConnection(remoteHost=self.TargetIP,remoteName=self.TargetIP)
            self._Connection = smbconn
            self.canConnect = True
            if type(smbconn._SMBConnection ) == smb3.SMB3:
                #smbconn.negotiateSession()
                
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

            #Neat Trick, It is okay if the login fails, as we only need to get the NTLMSSP AV data from the server NTLMSSP Challenge
            try:
                smbconn.login(user="administrator",password="admin123+")
                #smbconn._SMBConnection.login(user="",password="")
           
                print("a")
            except Exception as e:
                if "STATUS_NOT_SUPPORTED" in str(e):
                    self.NTLMSupport = False
                pass
            self.DNSName = smbconn.getServerDNSHostName()
            self.DNSDomain = smbconn.getServerDNSDomainName()
            self.NBDomain = smbconn.getServerDomain()
            self.NBName = smbconn.getServerName()
            self.ServerOS = smbconn._SMBConnection._Session['ServerOS']
            if smbconn._SMBConnection._Connection['ServerCapabilities']& NTLMSSP_NEGOTIATE_NTLM == NTLMSSP_NEGOTIATE_NTLM: # Not Correct Flags
                self.SupportsNTLMv1 = True

            


        except Exception as e:
            
                # no ntlm supported
                
            print("Something failed")
            print(e)
            pass

    def test_dialects(self):
        DialectsList = [smb.SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21,SMB2_DIALECT_30, SMB2_DIALECT_311]

        for i in DialectsList:
            try:
                smbconn = SMBConnection(remoteHost=self.TargetIP,remoteName=self.TargetIP,preferredDialect=i)
                self.SupportedSMBDilects.append(i)

                if smb.SMB_DIALECT in self.SupportedSMBDilects: # SMBv1 will support NTLMv1
                    self.SupportsNTLMv1 = True
            except:
                continue

    def test_NTLMv1(self):
        smbconn = SMBConnection(remoteHost=self.TargetIP,remoteName=self.TargetIP)
        try:
            smbconn.login(user="administrator",password="admin123+")
        except:
            pass

        ntlmssp_session = SMB2SessionSetup()
        if self.SigningRequired == True:
            ntlmssp_session["SecurityMode"] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
            ntlmssp_session["SecurityMode"] = SMB2_NEGOTIATE_SIGNING_ENABLED

        ntlmssp_session['Flags'] = 0
        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = getNTLMSSPType1(smbconn['ClientName'],"", smbconn['RequireSigning'])
        blob['MechToken'] = auth.getData()

        ntlmssp_session['SecurityBufferLength'] = len(blob)
        ntlmssp_session['Buffer']               = blob.getData()

        packet = self._Connection.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = ntlmssp_session

        smbconn._Session['PreauthIntegrityHashValue'] = smbconn['PreauthIntegrityHashValue']
        packetID = smbconn.sendSMB(packet)
        ans = smbconn.closerecvSMB(packetID)        





    

def main():
    smbtarget = "192.168.1.204"

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
    t.test_dialects()
    t.test_NTLMv1()
    t.print()
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