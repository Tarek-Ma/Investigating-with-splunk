# Investigating-with-splunk
SOC Level 1 incident investigation with Splunk logs on TryHackMe room.

## Introduction

SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

## Investigation start

 **Index**: All the required logs are ingested in the index **main**.

 **Task 1** :
 How many events were collected and Ingested in the index main?

 I just used the query " index=main " and the number of event will show

 **Task 2** :
 **On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?**

 The Event ID `4720` is triggered when a new user account is created.  
Using this query, we get a single result.  
By analyzing the log, we can see key fields such as:

- `Hostname`
- `Subject : Account Name`
- `Subject : Account Domain`

Under the **New Account** section we find `Account Name`, which contains the answer to the question.

**Task 3** : 
**On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?**

I first tried to search with Windows Event ID `4657`, which is normally used to detect registry changes. But i found any result.

So here, we use **Sysmon logs** instead.  
**Event ID `13`** in Sysmon is used when a registry value is created or modified.

Since we already know the `Hostname` from the previous task, i added it to the search

The result gave me **10 events**.  
Looking at the `TargetObject` field in the left panel, I found the **full path of the registry key** linked to the username of the previous task.

**Task 4** :
**Examine the logs and identify the user that the adversary was trying to impersonate.**

In the `User` field in the left-hand panel, we see two users: `James` and `Alberto`.  
The attacker changed a letter into a number to make the username look like the real one. Visually, it's very similar.

**Task 5** : 
**What is the command used to add a backdoor user from a remote computer?**

We already know the backdoor username, so we use a search with:  
`CommandLine=*backdoorusername*`

This gives us 6 events. In the `CommandLine` field on the left panel, we see 3 different values.

After a quick search on Google, we learn that **WMIC** can be used to connect to a remote computer and run commands.

The command using **WMIC** is the correct answer.

**Task 6** : 
**How many times was the login attempt from the backdoor user observed during the investigation?**


We can search using Windows Event IDs `4624` and `4625`, combined with the `backdoorusername` to check how many times login attempts were made.

Another method is to search for the username directly in the search bar.  
Then, in the left panel under the field `Category`, if there are login events, we will see the value `Logon`.

**Task 7** : 
**What is the name of the infected host on which suspicious Powershell commands were executed?**

We can filter with event ID `4103` and `4104` which shows **Powershell module logging** and **Powershell script block logging**
In the Hostname field on the left panel, we see only 1 result, which is the name of the infested host.

**Task 8** :
**PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?**

We can see the answer in the previous task

**Task 9** : 
**An encoded Powershell script from the infected host initiated a web request. What is the full URL?**

In the `Payload` field in the left pannel we see interesting values like : `/admin/get.php` `/news.php` `/login/process.php`. With the query `index=main EventID=4103 OR EventID=4104 *admin*` we find some results with the same encoded script, we decode it with Cyberchef -> Decode from **base64** then decode text in UTF16, we see a **path** with `/news.php` but the part before is also encoded in base64. We decode it with Cyberchef (base64 and decode text UTF16) and we get `http://10.10.10.5` so we have the full url ( combine with /news.php). The hint said that we have to defang it, we do it with Cyberchef too.
