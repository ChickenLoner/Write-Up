# [HackTheBox Sherlocks - Fragility](https://app.hackthebox.com/sherlocks/Fragility)
Created: 16/06/2024 14:19
Last Updated: 16/06/2024 18:18
* * *
![d28857e3da4cdb687230e6dbe0f6b1af.png](../../../_resources/d28857e3da4cdb687230e6dbe0f6b1af.png)

**Scenario:**
In the monitoring team at our company, each member has access to Splunk web UI using an admin Splunk account. Among them, John has full control over the machine that hosts the entire Splunk system. One day, he panicked and reported to us that an important file on his computer had disappeared. Moreover, he also discovered a new account on the login screen. Suspecting this to be the result of an attack, we proceeded to collect some evidence from his computer and also obtained network capture. Can you help us investigate it?

* * *
>Task 1: What CVE did the attacker use to exploit the vulnerability?

![cf96ffe3f2b5cd632eaae7b7ee92f45a.png](../../../_resources/cf96ffe3f2b5cd632eaae7b7ee92f45a.png)

Lets start with pcapng file and first thing that caught my eye is this http traffic that was sent to splunk web interface with python and double "Set-Cookie" header which likely to be a malicious script designed specifically for a CVE (PoC)

![97a3a10ac587121bb2ac167385c190dd.png](../../../_resources/97a3a10ac587121bb2ac167385c190dd.png)

Scrolling down for a bit then we can see that an attacker somehow obtained username and password and authenticated to splunk so to exploit this vulnerability an attacker need to be authenticated

![db90d54a039668f06aaa871e2b2e94a7.png](../../../_resources/db90d54a039668f06aaa871e2b2e94a7.png)

Scrolling down a little bit more then we can see what kind of vulnerability this python script aiming to exploit, Its uploaded malicious XLS file which also lead to Remote Code Execution

So this vulnerability is Authenticated Remote Code Execution on Splunk

Before going to search for CVE number, lets break down what will happened when this malicious xsl successfully triggered

- User Creation: The script starts by creating a new user named "nginx" without a password and sets their home directory to `/var/www/`.
- Password Setup: It decodes and reverses a base64 string to generate a password for the "nginx" user, then sets this password.
- Sudo Privileges: The "nginx" user is added to the "sudo" group, granting them administrative privileges.
- SSH Configuration: It creates an `.ssh` directory in the "nginx" user's home directory and adds a specific SSH public key to the `authorized_keys` file, allowing SSH access.
- Permissions: It ensures that the `/var/www/` directory and its contents are owned by the "nginx" user.
- History Clearing: Finally, it clears the "root" user's bash history to remove any trace of commands executed.

![1e18c12cea80ebad115a6bf700b7e02b.png](../../../_resources/1e18c12cea80ebad115a6bf700b7e02b.png)

Now we can search for the CVE number which directly lead us to PoC of this CVE directly

![83afec65906899f3130184c929e005bf.png](../../../_resources/83afec65906899f3130184c929e005bf.png)

Looking at contents of this script, its legitimate one

![1807b33d5c3c9010e7cf910ae540ac57.png](../../../_resources/1807b33d5c3c9010e7cf910ae540ac57.png)

Then I went back to Wireshark to confirm that an attacker accessed to targeted machine on port 22.

```
CVE-2023-46214
```

>Task 2: What MITRE technique does the attacker use to maintain persistence?

![fb58933495d3da0d993a7e42cc5c3661.png](../../../_resources/fb58933495d3da0d993a7e42cc5c3661.png)

An attacker created a new user first then added password and ssh public key for it so the technique that will suit this scenario the most if "Create Account"

```
T1136
```

>Task 3: John has adjusted the timezone but hasn't rebooted the computer yet, which has led to some things either being updated or not updated with the new timezone. Identifying the timezone can assist you further in your investigation. What was the default timezone and the timezone after John's adjustment on this machine?

![6edc0f713b3293fde9bd1a519498b80d.png](../../../_resources/6edc0f713b3293fde9bd1a519498b80d.png)

First I used `grep -ri "time zone" .` first to find anything related to timezone changed and we can see that it changed to "Asia/Ho_Chi_Minh" which is UTC+07

![adf387d0d0e7c7e57f688f3753afc7e6.png](../../../_resources/adf387d0d0e7c7e57f688f3753afc7e6.png)

I couldn't figure it out how to find default timezone, I thought it was UTC+00 but Its incorrect then I searched for "america" or anything that related to system setup which land me with `debconf` logs which specifically related to setting the country during installation and it was North America

![30305e73fc5f0adcf49cac57fc507332.png](../../../_resources/30305e73fc5f0adcf49cac57fc507332.png)

There is many time we can use but the right answer is MT (Mountain Time UTC-07)

```
utc-07/utc+07
```

>Task 4: When did the attacker SSH in? (UTC)

![3120af46282b6e1179946950f5162819.png](../../../_resources/3120af46282b6e1179946950f5162819.png)

Go back to Wireshark, we need to pick time of the packet after key exchange 

```
04-14 15:00:21
```

>Task 5: How much time has passed from when the user was first created to when the attacker stopped using SSH?

![5c8f91e05e90647cd80e73921b7062e7.png](../../../_resources/5c8f91e05e90647cd80e73921b7062e7.png)

This time, we need to investigate `auth.log` and filter for connection disconnected and useradd event and calculate duration between them

08:03:08 - 08:00:13 = 00:02:55

```
00:02:55
```

>Task 6: What is the password for the account that the attacker used to backdoor?

![e9734564f02433ac3078cec555c68496.png](../../../_resources/e9734564f02433ac3078cec555c68496.png)

![8b025a76f0acfa71dc5b76a542cd0c9b.png](../../../_resources/8b025a76f0acfa71dc5b76a542cd0c9b.png)

Execute this command on our bash then we will have "nginx" user password

![26e9c3b9063f02b85aab3591d6d02caa.png](../../../_resources/26e9c3b9063f02b85aab3591d6d02caa.png)

```
f8287ec2-3f9a-4a39-9076-36546ebb6a93
```

>Task 7: There is a secret in the exfiltrated file, what is its content?

![98bb369933dfbcc51c9d304473b6714d.png](../../../_resources/98bb369933dfbcc51c9d304473b6714d.png)

Command History from `auth.log` tells us that there is an `Important.pdf` was moved to `/var/www/` then used openssl to encrypted it and lastly it was deleted

![fdfda327e101c797ce1eb26c7ded029c.png](../../../_resources/fdfda327e101c797ce1eb26c7ded029c.png)

So I went to `\var\www\` and we can see that there is `.bash_history` here

![fd6b9319b2d303d178cd9a5efeedf345.png](../../../_resources/fd6b9319b2d303d178cd9a5efeedf345.png)

Now we can see that not just deleted, an attacker sent encrypted file to his system on port 8080

![91f616db7a3783fe93f7fb0ae75c58f0.png](../../../_resources/91f616db7a3783fe93f7fb0ae75c58f0.png)

So we can go back to wireshark and find this connection

![e3efa431222cd69800644880e3060468.png](../../../_resources/e3efa431222cd69800644880e3060468.png)

Lets save this file as Raw format

![7c82f4a59c75ed6bb3146298c88ef133.png](../../../_resources/7c82f4a59c75ed6bb3146298c88ef133.png)

Then convert it back to ascii and decode base64 with `cat raw.raw | dd conv=ascii | base64 -d > encrypted_data.zip`

![f337e769e7a50d1adb7910f7756c4815.png](../../../_resources/f337e769e7a50d1adb7910f7756c4815.png)

Lastly we will use `openssl enc -d -aes-256-cbc -in encrypted_data.zip -out data.zip -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d` to recover compressed file.

![48edb0f278ef4490e1aa5090d5417b7d.png](../../../_resources/48edb0f278ef4490e1aa5090d5417b7d.png)

Open a file inside compressed file then we will have this Highest privilege credentials

```
Th3_uNs33n_P4$$w0rd_is_th3_m05t_s3cur3
```

>Task 8: What are the username and password that the attacker uses to access Splunk?

![052111c1cd52f60b4b354ddf4ca77863.png](../../../_resources/052111c1cd52f60b4b354ddf4ca77863.png)

If you remembered that to exploit splunk, an attacker need to be authenticated so we can go back to wireshark and get user credential that was used to access splunk

```
johnnyC:h3Re15j0hnNy
```

![332eb67b5b1a006bc93e2ee02469efa5.png](../../../_resources/332eb67b5b1a006bc93e2ee02469efa5.png)
* * *
