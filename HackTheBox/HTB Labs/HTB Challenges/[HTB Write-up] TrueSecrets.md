# [HackTheBox - TrueSecrets](https://app.hackthebox.com/challenges/TrueSecrets)
Created: 21/07/2024 18:31
Last Updated: 21/07/2024 21:42
***
**DIFFICULTY**: Easy
**CATEGORY**: Forensics
**CHALLENGE DESCRIPTION** 
Our cybercrime unit has been investigating a well-known APT group for several months. The group has been responsible for several high-profile attacks on corporate organizations. However, what is interesting about that case, is that they have developed a custom command & control server of their own. Fortunately, our unit was able to raid the home of the leader of the APT group and take a memory capture of his computer while it was still powered on. Analyze the capture to try to find the source code of the server.
***
## Volatility Time
![6a174d701bb71572d27efc814c96225a.png](../../../_resources/6a174d701bb71572d27efc814c96225a.png)

We already know that we got a memory capture of C2 server so lets determine which volatility profile to use with `vol.py -f TrueSecrets.raw imageinfo`

And the result show us that this C2 was running on Windows

![355822fe503c06ff8f6b4186df1d131d.png](../../../_resources/355822fe503c06ff8f6b4186df1d131d.png)

So I used `vol3 -f TrueSecrets.raw windows.cmdline` to display all command line arguments of each process that were running on that machine when this memory image was taken and we can see that `7zFM.exe` was compressed `backup_development.zip` which should be a file that we are after

![3468e17cfa349a4584adb178f4c02730.png](../../../_resources/3468e17cfa349a4584adb178f4c02730.png)

So I used `vol.py -f TrueSecrets.raw --profile=Win7SP1x86_23418 filescan | grep -i "backup_development.zip"` to determine if a file can be dumped from this memory dump and we can also see physical address of this file on this memory image which we can dump it with `vol.py -f TrueSecrets.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000000bbf6158 -D /tmp/`

![bbb4456a466d21971408fdba0acbf40c.png](../../../_resources/bbb4456a466d21971408fdba0acbf40c.png)

After unzip a file, we will have this TrueCrypt volume file before we get into an actual script of this C2 server

![88deede1d20c9a46db67326f94df57f9.png](../../../_resources/88deede1d20c9a46db67326f94df57f9.png)

But we also have to get TrueCrypt password from this memory image first with `vol.py -f TrueSecrets.raw --profile=Win7SP1x86_23418 truecryptpassphrase` and now, we are ready to recover files

## Truecrypt File Recovery
![ba306b757a57ca7136802057b6cf6055.png](../../../_resources/ba306b757a57ca7136802057b6cf6055.png)
We can use Veracrypt to decrypt and mount TrueCrypt but there is a problem here, if you are using [Veracrypt version 1.26.7 or above then TrueCrypt decryption will not be there](https://superuser.com/questions/1210798/can-veracrypt-open-an-old-truecrypt-container) so we have to use [VeraCrypt 1.25.9](https://www.veracrypt.fr/en/Downloads_1.25.9.html) or below when TrueCrypt was still supported

![da55308a458494afeb0d3e71d53195f8.png](../../../_resources/da55308a458494afeb0d3e71d53195f8.png)

Using passphrase we got to mount it to our local drive

![663ebc46f9270e31dbdaae2d4287b440.png](../../../_resources/663ebc46f9270e31dbdaae2d4287b440.png)

After mounting, we finally have a script that running on C2 server and log file that was encrypted in `sessions` folder 

![ecdf6e3efdbbcb9fdf99898762cd12c6.png](../../../_resources/ecdf6e3efdbbcb9fdf99898762cd12c6.png)

Lets examine `AgenServer.cs`, it will receive a connection on port 40001 and if there is any infected machine successfully connected to this server then `sessionID` will be generated and it will wait for command on console to send to infected system, then infected system will also send response of that command back to this server and will be logged to log file respectively created for each `sessionID` and this log file will also be encrypted so a flag might be in 1 of 3 log files that we found earlier

![b6f6e66378dbae3f635f8279ae41d77b.png](../../../_resources/b6f6e66378dbae3f635f8279ae41d77b.png)

Now lets take a look at `Encrypt` function, it seems like this server is using DES to encrypt message then encode with base64 which luckily for us that we can get `key` and `iv` here so lets use CyberChef to get a flag

- `5818acbe-68f1-4176-a2f2-8c6bcb99f9fa.log.enc`
![3fac508fe6f11ece01c393f96a18a1f9.png](../../../_resources/3fac508fe6f11ece01c393f96a18a1f9.png)
- `c65939ad-5d17-43d5-9c3a-29c6a7c31a32.log.enc`
![04b9e5af0317c0a350ee5ac6f20c619d.png](../../../_resources/04b9e5af0317c0a350ee5ac6f20c619d.png)
- `de008160-66e4-4d51-8264-21cbc27661fc.log.enc`
![cc341721dbd7e403e5986bdfa12a1ce1.png](../../../_resources/cc341721dbd7e403e5986bdfa12a1ce1.png)

## Submit the flag

```
HTB{570r1ng_53cr37_1n_m3m0ry_15_n07_g00d}
```

![26101e8d9094a6791e58c0ba7acb7dd4.png](../../../_resources/26101e8d9094a6791e58c0ba7acb7dd4.png)
***

