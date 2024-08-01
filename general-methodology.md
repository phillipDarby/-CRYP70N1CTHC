# General Methodology

If you have anything that you use in your methodology which is useful please let me know and I'll share

### &#x20;<a href="#general-oscp-ctf-tips" id="general-oscp-ctf-tips"></a>

### General OSCP/CTF Tips <a href="#general-oscp-ctf-tips" id="general-oscp-ctf-tips"></a>

Restart the box - wait 2+ minutes until it comes back and all services have started



#### &#x20;<a href="#for-every-open-port-tcp-udp" id="for-every-open-port-tcp-udp"></a>

#### For every open port TCP/UDP <a href="#for-every-open-port-tcp-udp" id="for-every-open-port-tcp-udp"></a>

```
http://packetlife.net/media/library/23/common_ports.pdf
```

* Find service and version
* Find known service bugs
* Find configuration issues
* Run nmap port scan / banner grabbing

#### &#x20;<a href="#google" id="google"></a>

#### Google <a href="#google" id="google"></a>

* Every error message
* Every URL path
* Every parameter to find versions/apps/bugs
* Every version exploit db
* Every version vulnerability

#### &#x20;<a href="#if-app-has-auth" id="if-app-has-auth"></a>

#### If app has auth <a href="#if-app-has-auth" id="if-app-has-auth"></a>

* User enumeration
* Password bruteforce
* Default credentials google search



**If everything fails try:**

```
nmap --script exploit -Pn $ip
```

### &#x20;<a href="#individual-host-scanning" id="individual-host-scanning"></a>

### Individual Host Scanning <a href="#individual-host-scanning" id="individual-host-scanning"></a>

#### &#x20;<a href="#service-scanning" id="service-scanning"></a>

#### Service Scanning <a href="#service-scanning" id="service-scanning"></a>

#### &#x20;<a href="#webapp" id="webapp"></a>

#### WebApp <a href="#webapp" id="webapp"></a>

```
https://owasp.org/www-project-web-security-testing-guide/v42/
```

* Nikto
* dirb
* dirbuster
* wpscan
* dotdotpwn/LFI suite
* view source
* davtest/cadeavar
* droopscan
* joomscan
* LFI\RFI test
* Wapalyzer

#### &#x20;<a href="#linux-windows" id="linux-windows"></a>

#### Linux\Windows <a href="#linux-windows" id="linux-windows"></a>

* snmpwalk -c public -v1 $ip 1
* smbclient -L //$ip
* smbmap -H $ip
* rpcinfo
* Enum4linux



**Anything Else**

* nmap scripts
* hydra
* MSF Aux Modules
* Download software....uh'oh you're at this stage

### &#x20;<a href="#exploitation" id="exploitation"></a>

### Exploitation <a href="#exploitation" id="exploitation"></a>

* Gather version numbers
* Searchsploit
* Default Creds
* Creds previously gathered
* Download the software

### &#x20;<a href="#stuck" id="stuck"></a>

### Stuck? <a href="#stuck" id="stuck"></a>



**Things to consider**

1. Have you confirmed the service on the port manually and googled all the things (the SSH string, the banner text, the source)?
2. Is there a service that will allow you to enumerate something useful (i.e. usernames) but maybe doesn't make that obvious (e.g. RID brute-force through SMB with crackmapexec or lookupsid.py)?
3. Have you used the best wordlist possible for your tasks (is there a better/bigger directory list? Is there a SecLists cred list for this service?)
4. Have you fuzzed the directories you have found for a) more directories, or b) common filetypes -x php,pl,sh,etc
5. Have you tried some manual testing (MySQL, wireshark inspections)
6. Have you collected all the hashes and cracked them?
7. Have you tried ALL COMBINATIONS of the username/passwords and not just the pairs given? Have you tried them across all services/apps?
8. Do the version numbers tell you anything about the host?
9. Have you tried bruteforce (cewl, patator)?
10. Can you think of a way to find more information: More credentials, more URLs, more files, more ports, more access?
11. Do you need to relax some of the terms used for searching? Instead of v2.8 maybe we check for anything under 3.
12. Do you need a break?

### &#x20;<a href="#capture-info" id="capture-info"></a>

### Capture info <a href="#capture-info" id="capture-info"></a>

* Screenshot of IPConfig/WhoamI
* Copy proof.txt
* Dump hashes
* Dump SSH Keys
* Delete files
* Reset Machine
