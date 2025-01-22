### Caldera

This is a Zeek based Caldera detector.  It detects Caldera beacons and agent downloads.

#### Example:

Running the sandcat.pcap in the testing/Traces directory through this logic produces:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2025-01-22-17-37-59
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1734546921.034784	CHhAvVGS1DHFjwGM9	172.18.0.3	58326	172.18.0.2	8888	-	-	-	tcp	Caldera::SuspiciousFileDownload	Caldera file download detected: file 'sandcat.go', platform 'linux', User-Agent 'curl/7.68.0'	Caldera Suspicious File Download	172.18.0.3	172.18.0.2	8888	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1734546938.807708	C4J4Th3PJpwUYZZ6gc	172.18.0.3	35540	172.18.0.2	8888	-	-	-	tcp	Caldera::SandcatC2Detected	Potential beacon detected to /beacon with User-Agent 'Go-http-client/1.1'	-	172.18.0.3	172.18.0.2	8888	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2025-01-22-17-37-59
```
