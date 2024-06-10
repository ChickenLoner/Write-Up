# [Blue Team Labs Online - Piggy](https://blueteamlabs.online/home/investigation/piggy-aij2bd8h2)
Created: 10/06/2024 12:20
Last Updated: 10/06/2024 13:48
* * *
<div align=center>

![47645d56c73466806680dcd81d946c3f.png](../../../_resources/47645d56c73466806680dcd81d946c3f.png)
</div>

>Investigate some simple network activity in Wireshark!

>**Tags**: Wireshark, ATT&CK, OSINT
* * *

**Scenario**
Investigate some simple network activity in Wireshark! You can launch Wireshark in a terminal with the command 'wireshark'. The questions are mapped to the four PCAPs on the Desktop.

* * *
## Investigation Submission
>PCAP One) What remote IP address was used to transfer data over SSH? (Format: X.X.X.X)

![51c6d20bb66f7afc629b2fd1d5645fab.png](../../../_resources/51c6d20bb66f7afc629b2fd1d5645fab.png)
Open PCAP ONE file then filter for SSH then we will have this external IP address communicating with internal IP address

```
35.211.33.16
```

>PCAP One) How much data was transferred in total? (Format: XXXX M)

![4cf6ab719cac0cafc6d412934a607328.png](../../../_resources/4cf6ab719cac0cafc6d412934a607328.png)

Open Conversations Statistics then we can see how many bytes were transfer on this conversation.

```
1131 M
```

>PCAP Two) Review the IPs the infected system has communicated with. Perform OSINT searches to identify the malware family tied to this infrastructure (Format: MalwareName)

![9b9e1cad56e0e2c97dfa399a556bf6f8.png](../../../_resources/9b9e1cad56e0e2c97dfa399a556bf6f8.png)

Open Conversations Statistics and search all external IP addresses on VirusTotal

![ce50d94e27dc44109b0e26f75e401a05.png](../../../_resources/ce50d94e27dc44109b0e26f75e401a05.png)

Then we will have this IP address that were used for Trickbot C2

```
trickbot
```

>PCAP Three) Review the two IPs that are communicating on an unusual port. What are the two ASN numbers these IPs belong to? (Format: ASN, ASN)

![9c09f76213ee8586b6ed36306b70bd57.png](../../../_resources/9c09f76213ee8586b6ed36306b70bd57.png)

Open Endpoints Statistic and go to TCP, we can see that last 2 IP addresses were communicating on port 8000 and 8080

![99a46f0b8f9a32a2f286dfe01c474250.png](../../../_resources/99a46f0b8f9a32a2f286dfe01c474250.png)

![d943facc01c1d144913a297142a0ecdd.png](../../../_resources/d943facc01c1d144913a297142a0ecdd.png)

I couldn't find ASN number on Wireshark so I have to get them from VirusTotal

```
14061, 63949
```

>PCAP Three) Perform OSINT checks. What malware category have these IPs been attributed to historically? (Format: MalwareType) 

![90b829163afd7dc4db23377a27e5c2e9.png](../../../_resources/90b829163afd7dc4db23377a27e5c2e9.png)

Find those uncommon ports to inspect which kind of data that were being transferred then we can see it does look like they were communicating with json 

Another indicator is mining which mean it could be cryptominer malware.

![4eb6e9c8e0d604410b8e3df23191005f.png](../../../_resources/4eb6e9c8e0d604410b8e3df23191005f.png)

Search for these 2 IP addresses on Google then I found there is a blog list containing both of them.

![24383e373d87c680a3c043dd8333b098.png](../../../_resources/24383e373d87c680a3c043dd8333b098.png)

Confirmed that this IP address associated with cryptominer

```
miner
```

>PCAP Three) What ATT&CK technique is most closely related to this activity? (Format: TXXXX)

![79e18fbf1938019da9dd684ec61fd76f.png](../../../_resources/79e18fbf1938019da9dd684ec61fd76f.png)

Cryptomining will use resource on infected machine to mine cryptocurrency so MITRE ATT&CK technique that perfectly described this is Resource Hijacking

```
T1496
```

>PCAP Four) Go to View > Time Display Format > Seconds Since Beginning of Capture. How long into the capture was the first TXT record query made? (Use the default time, which is seconds since the packet capture started) (Format: X.xxxxxx)

![9a61091cfd5251093b24148f6feec74f.png](../../../_resources/9a61091cfd5251093b24148f6feec74f.png)

I used Find Packet to find for TXT record query directly

```
8.527712
```

>PCAP Four) Go to View > Time Display Format > UTC Date and Time of Day. What is the date and timestamp? (Format: YYYY-MM-DD HH:MM:SS)

![fd23f060bd5009dc6a5be3e0d652bc6f.png](../../../_resources/fd23f060bd5009dc6a5be3e0d652bc6f.png)
```
2024-05-24 10:08:50
```

>PCAP Four) What is the ATT&CK subtechnique relating to this activity? (Format: TXXXX.xxx)

![a3f1e91ad583f8914a06f1270a2e95f5.png](../../../_resources/a3f1e91ad583f8914a06f1270a2e95f5.png)

We can see this weird domain were in TXT record which probably indicate that it was used for C2 communication or DNS tunneling

![fcfb1c9c0abbcb1736ee7876178c2aa0.png](../../../_resources/fcfb1c9c0abbcb1736ee7876178c2aa0.png)

```
T1071.004
```

![129fb9dbd4301c56947a81beb1f26074.png](../../../_resources/129fb9dbd4301c56947a81beb1f26074.png)
* * *