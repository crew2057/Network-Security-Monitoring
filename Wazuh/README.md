## Objective
Performing host based intrusion detection by writing rules in wazuh.

## Network Diagram
<img src="https://i.postimg.cc/HxknGsHm/wazuh.png">

## Activities
- **Detect a group with "malware" at the beginning of the name being added to the CentOs.**
<img src="https://i.postimg.cc/05pktw7G/Wazuh-rulewriting.jpg">

- **Detect a group with "malware" being added to a Windows system.**
<img src="https://i.postimg.cc/prZtPKB7/Wazuh-rulewriting.jpg">

- **Detect the root user's password change in linux system.**
<img src="https://i.postimg.cc/ncR6TFSz/Screenshot-2026-03-29-at-21-01-35.png">

- **Detect process creation event using PowerShell or Command prompt.**
<img src="https://i.postimg.cc/Wb3yDRpD/Screenshot-2026-03-29-at-21-03-39.png">

- **Detect 5 MMC process creations in 120 seconds via Sysmon**
<img src="https://i.postimg.cc/fLzK6XJL/wazuh-sysmon.jpg">

- **Detect outbound UDP network connections over port 53 to IPs that are not 172.16.3.100**
<img src="https://i.postimg.cc/vZw5J9Nj/wazuh-sysmon.jpg">

- **Detect commands _ipconfig, net, net1, ping, nslookup, netsh_ not run under either cmd.exe or powershell.exe**
<img src="https://i.postimg.cc/Ghxk19nG/wazuh-sysmon.jpg">

- **Detect multiple file creation within short-time frame.**
<img src="https://i.postimg.cc/tJHVKGr5/wazuh-sysmon.jpg">

- **Detect 5 registry items deletion by the same user within 1 minute.**
<img src="https://i.postimg.cc/pVY9m7cR/wazuh-sysmon.jpg">
