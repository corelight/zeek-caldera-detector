# zeek-caldera-detector

**`zeek-caldera-detector`** is a Zeek-based package for detecting Caldera beacons and agent downloads. It is designed to identify suspicious activities associated with Caldera C2 frameworks, including `Sandcat`, `Ragdoll`, and `Manx`.

This package provides robust mechanisms for monitoring HTTP traffic, detecting beacon patterns, and identifying suspicious file downloads based on pre-defined indicators.

## Features

- **Caldera C2 Detection**:
  - Detects HTTP beacons (`Sandcat`, `Ragdoll`, and `Manx`) based on unique URI paths and User-Agent strings.
  - Recognizes TCP and UDP-based Manx C2 activities using Zeek signatures.
- **Suspicious File Download Detection**:
  - Tracks suspicious filenames (e.g., `sandcat.go`, `manx.go`, `ragdoll.py`) in HTTP headers.
  - Generates alerts when these files are downloaded, including platform and User-Agent information.

## How It Works

The module uses the following mechanisms for detection:
1. **HTTP Headers and Messages**:
   - Monitors HTTP headers and payloads for indicators of Caldera activity.
   - Checks for specific filenames, platforms, and User-Agent strings in download traffic.
2. **Zeek Signatures**:
   - Identifies TCP and UDP C2 activity based on payload patterns in network traffic.
   - Includes support for both active C2 commands and reply detection.

## Example

Running the provided `sandcat.pcap` from the `testing/Traces` directory through this logic produces the following alerts:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2025-01-22-21-21-11
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1734546921.034784	CHhAvVGS1DHFjwGM9	172.18.0.3	58326	172.18.0.2	8888	-	-	-	tcp	Caldera::SuspiciousFileDownload	Caldera file download detected: file 'sandcat.go', platform 'linux', User-Agent 'curl/7.68.0'	-	172.18.0.3	172.18.0.2	8888	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
1734546938.807708	C4J4Th3PJpwUYZZ6gc	172.18.0.3	35540	172.18.0.2	8888	-	-	-	tcp	Caldera::C2Detected	Potential Sandcat beacon detected to /beacon with User-Agent 'Go-http-client/1.1'	-	172.18.0.3	172.18.0.2	8888	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2025-01-22-21-21-11
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for bug fixes, enhancements, or new feature suggestions.

## License
This project is licensed under the MIT License. See the COPYING file for details.
