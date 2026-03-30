## Objective
Rule writing with Suricata to alert on rule match in the provided network file.

## Activities
- Detect windows updates
<pre>
alert tcp 10.5.24.101 any -> any 80 (msg:"Windows Update";\
  flow:from_client,established;\
  http.host; content:"ctldl.windowsupdate.com";\
  http.uri; content:"/msdownload"; startswith;\
  http.user_agent; content:"10.0"; endswith;\
  sid:1000001; rev:1;
</pre>

- Detect executable file being downloaded using flowbits
<pre>
alert tcp 10.11.6.101 any -> 212.47.220.51 80 (msg:"Suspicious file request";\
  flow:to_server,established;
  http.uri; content: "/VqUuJ3B7/";\
  flowbits:set, file_download: flowbits:noalert;\
  sid:1000002; rev:1;
  
alert tcp 212.47.220.51 80 -> 10.11.6.101 any (msg: "Suspicious File Download";\
  flow:to_client,established;\
  http.header: content: "Tue, 01 Jan 1970 00:00:00 GMT";\
  http.response_body; content: "MZ";\
  flowbits:isset, file_download;\
  sid:1000003; rev:1;
</pre>

- Detect access of share on a domain controller with path to assumed malware.
<pre>
alert tcp any any -> any any (msg:"Malware in domain controller";\
  flow:to_server,established;\
  smb_share; content:"sysvol";\
  sid:1000003; rev:1;)
</pre>

- Identify executable file framed as portable network graphics.
<pre>
alert tcp any any -> any 80 (msg:"Image request";\
  flow:to_server,established;\
  http.uri; content:"radiance.png";\
  flowbits:set, mal_download; flowbits:noalert;\
  sid:1000004; rev:1;)
  
alert tcp any 80 -> any any (msg:"Malicious file download";\
  flow:to_client,established;\
  http.content_type; content:"image/png";\
  http.response_body; content:"MZ";\
  flowbits:isset, mal_download;\
  sid:1000005; rev:1;)
</pre>

- Capturing C2 communication occurred over http
<p>We could match on the plaintext content in the body.</p>
<pre>
alert tcp 192.168.1.5 1337 -> 192.168.1.10 any (msg:"C2 communication";\
  tcp.flags:PA;\
  content:"Run this command for totally not malicious reasons";\
  flowbits:set, command_exec; flowbits:noalert;\
  sid:1000006; rev:1;)

alert tcp 192.168.1.10 any -> 192.168.1.5 1337 (msg:"C2 communication";\
  tcp.flags:PA;\
  flowbits:isset, command_exec;\
  sid:1000007; rev:1;)
</pre>

- Capturing C2 communication occurred over TLS 1.2
<p>The content of the body would be encrypted for TLS 1.2. However, metadata information would still be in plaintext, so we could use Certificate Authority details to identify the C2 channel.</p>
<pre>
alert tcp 192.168.1.5 1337 -> 192.168.1.10 any (msg:"Self signed certificate";\
  tls.version:1.2;\
  tls.cert_issuer; content:"notmalware Certificate Authority";\
  tls.cert_serial; content:"05:96:1f:05:96:1f:05:96:1f:05:96:1f:05:96:1f:05:96:1f:05:96:1f:05:96";\
  sid:1000008; rev:1;)
</pre>

- Capturing C2 communication occurred over TLS 1.3
<p>As TLS 1.3 encrypts both the data and most of the metadata, it was difficult to write a good rule.
First thing is to find the common terms within all the message relays that occurred between the
server and the client. However, there was this unique JA3 and JA3S hashes for fingerprinting
TLS/SSL.</p>
<pre>
alert tcp 192.168.1.5 1337 -> 192.168.1.10 any (msg:"Self signed certificate";\
  ja3s.hash; content:"13ab53628cb84374fe9238da425681ab"
  sid:1000009; rev:1;)
</pre>
