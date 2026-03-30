## Objective
Using Wireshark to search through a traffic capture and derive conclusions about the packets that are captured.

## Activities
- **Determine the client recording the capture.**
<img src="https://i.postimg.cc/kXZGtmC2/Screenshot-2026-03-29-at-19-19-23.png" />
<p>192.168.1.6 seems to be our client as it is engaged in almost 100% of conversations that we captured. We can observe this data from IPV4 statistics.</p>

- **Determine Operating system of the client in the capture.**
<img src="https://i.postimg.cc/q7rk8B5f/Screenshot-2026-03-29-at-19-22-13.png">
<p>Windows NT 10 x64 is the operating system that the user is running. It could be verified from the TTL (Time to leave) value as well as we can see the OS information in the useragent field of http protocol.</p>

- **Find out the username/password for the FTP server**
<img src="https://i.postimg.cc/SKtkHLxP/Screenshot-2026-03-29-at-19-27-12.png">
<p>After filtering for ftp protocol, we can see that user was able to successfully login into the
system using username “bj” and password “Password1!”.</p>

- **Identify that file being transferred over FTP**
<img src="https://i.postimg.cc/T3t6Wjgy/Screenshot-2026-03-29-at-19-29-06.png">
<p>The file that was transferred over FTP was AppleCat.jfif and I was able to export it by
selecting FTP-DATA from wireshark export object feature.</p>

- **Identify the URL over which file name "success.txt" is being transferred and determine why it was being transferred.**
<img src="https://i.postimg.cc/3N1Lb1K2/Screenshot-2026-03-29-at-19-32-45.png">
<p>The file is from URL hxxp[://]detectportal[.]firefox[.]com. We can see that
the content of the file success.txt is just “success”. The URL is used by Firefox when
detecting whether it is using a captive portal. A captive portal is a webpage that the user of
a public network is required to view and interact with before they can access the network.
It is typically used by business centers, airports, hotel lobbies, coffee shops and other public
venues that offer free Wi-Fi hotspots for internet users.</p>

- **Figure out the purpose of DNS request for "doh.test"**
<img src="https://i.postimg.cc/90mbT9Gw/Screenshot-2026-03-29-at-19-35-04.png">
<p>The client is likely trying to connect to a service or application associated with the domain
doh.test. A DNS lookup is a necessary first step for almost all network communication. The
client needs to know the IP address of the server it's trying to reach, and it gets that
information from a DNS server if that is present.</p>

- **Find out all the HTTP 301 responses and find the end goal of them**
<img src="https://i.postimg.cc/W3n624QZ/Screenshot-2026-03-29-at-19-37-15.png">
<p>The http response code 301 means the requested url have been moved permanently. Closer look into redirected traffic shows movement of http requests to https for more secured connection.
<ul>
<li>In case of request to ’23.99.192.132’, the client after getting response code of 301,
terminated the connection on to port 80 with [FIN] flag and made request to https (port
443) for secured communication. Following the streams we can see that the connection
was successful with the presence of client hello, key exchange, server hello and transfer of
application data between client and server.</li>
<li>In case of request to ‘151.101.65.67’, the client after getting response code of 301,
teminated the connection to port 80 with [FIN] flag.</li>
<li>In case of request to ’151.101.193.67’, the client after getting response code of 301,
terminated the connection on to port 80 with [FIN] flag and made request to https (port
443) for secured communication. Following the streams we can see that the connection
was successful with the presence of client hello, key exchange, server hello and
transfer of application data between client and server.</li></ul> </p>
