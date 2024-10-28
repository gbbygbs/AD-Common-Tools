#### Sharpview/Powerview
 A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting.
```bash
# PowerView
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
# Sharpview
https://github.com/dmchell/SharpView
```

#### Bloodhound
Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the SharpHound PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a Neo4j database for graphical analysis of the AD environment.
```bash
https://github.com/BloodHoundAD/BloodHound
```

#### SharpHound
The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.
```bash
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
```

#### Bloodhound.py
A Python-based BloodHound ingestor based on the Impacket toolkit. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis.
```bash
https://github.com/dirkjanm/BloodHound.py
```

#### Kerbrute
A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing.
```bash
https://github.com/ropnop/kerbrute
```

#### Impacket toolkit
A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.
```bash
https://github.com/fortra/impacket
```

#### Responder
Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.
```bash
https://github.com/lgandx/Responder
```

#### Inveigh.ps1
Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.
```bash
https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1
```

#### C# Inveigh (InveighZero)
The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes.
```bash
https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh
```

#### rpcinfo
The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges.
```bash
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo
```

#### rpcclient
A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.
```bash
https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
```

#### CrackMapExec (CME)
CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL.
```bash
https://github.com/byt3bl33d3r/CrackMapExec
```

#### Rubeus
Rubeus is a C# tool built for Kerberos Abuse.
```bash
https://github.com/GhostPack/Rubeus
```

#### GetUserSPNs.py
Another Impacket module geared towards finding Service Principal names tied to normal users.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
```

#### Hashcat
A great hash cracking and password recovery tool.
```bash
https://hashcat.net/hashcat/
```

#### enum4linux-ng/enum4linux
A tool for enumerating information from Windows and Samba systems.
A rework of the original Enum4linux tool that works a bit differently.
```bash
# enum4linux-ng
https://github.com/cddmp/enum4linux-ng
# enum4linux
https://github.com/CiscoCXSecurity/enum4linux
```

#### Ldapsearch
Built-in interface for interacting with the LDAP protocol.
```bash
https://linux.die.net/man/1/ldapsearch
```

#### windapsearch
A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.
```bash
https://github.com/ropnop/windapsearch
```

#### DomainPasswordSpray.ps1
DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.
```bash
https://github.com/dafthack/DomainPasswordSpray
```

#### LAPSToolKit
The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).
```bash
https://github.com/leoloobeek/LAPSToolkit
```

#### smbmap
SMB share enumeration across a domain.
```bash
https://github.com/ShawnDEvans/smbmap
```

#### psexec.py
Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
```

#### wmiexec.py
Part of the Impacket toolkit, it provides the capability of command execution over WMI.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
```

#### Snaffler
Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.
```bash
https://github.com/SnaffCon/Snaffler
```

#### smbserver.py
Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py
```

#### setspn.exe
Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.
```bash
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)
```

#### mimikatz
Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host.
```bash
https://github.com/ParrotSec/mimikatz
```

#### secretsdump.py
Remotely dump SAM and LSA secrets from a host.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
```

#### evil-winrm
Provides us with an interactive shell on a host over the WinRM protocol.
```bash
https://github.com/Hackplayers/evil-winrm
```

#### mssqclient.py
Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py
```

#### noPac.py
Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.
```bash
https://github.com/Ridter/noPac
```

#### rpcdump.py
Part of the Impacket toolset, RPC endpoint mapper.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py
```

#### CVE-2021-1675.py
Printnightmare PoC in python.
```bash
https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py
```

#### ntlmrelayx.py
Part of the Impacket toolset, it performs SMB relay attacks.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py
```

#### PetitPotam.py
PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
```bash
https://github.com/topotam/PetitPotam
```

#### gettgtpkinit.py
Tool for manipulating certificates and TGTs.
```bash
https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py
```

#### getnthash.py
This tool will use an existing TGT to request a PAC for the current user using U2U.
```bash
https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py
```

#### adidnsdump.py
A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer.
```bash
https://github.com/dirkjanm/adidnsdump
```

#### gpp-decrypt
Extracts usernames and passwords from Group Policy preferences files.
```bash
https://github.com/t0thkr1s/gpp-decrypt
```

#### GetNPUsers.py
Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py
```

#### lookupsid.py
SID bruteforcing tool.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py
```

#### ticketer.py
A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
```

#### raiseChild.py
Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation.
```bash
https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py
```

#### Active Directory Explorer
Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.
```bash
https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer
```

#### PingCastle
Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on [CMMI](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) adapted to AD security).
```bash
https://www.pingcastle.com/documentation/
```

#### Group3r
Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).
```bash
https://github.com/Group3r/Group3r
```

#### ADrecon
A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.
```bash
https://github.com/adrecon/ADRecon
```