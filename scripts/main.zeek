module Caldera;

export {
	## Suspicious filenames to detect in file download traffic.
	global suspicious_filenames =
		set("sandcat.go", "manx.go", "ragdoll.py") &redef;
}

redef enum Notice::Type += {
	## Potential MITRE Caldera(tm) C2 detected.
	Caldera::C2Detected,

	## Potential MITRE Caldera(tm) agent download detected.
	Caldera::SuspiciousFileDownload,
};

redef record HTTP::Info += {
	# If set, a suspicious filename was detected.
	caldera_filename: string &optional;
};

event http_header(c: connection, is_orig: bool, original_name: string,
    name: string, value: string)
	{
	if ( ! is_orig || ! c$http?$method || ! c$http?$uri )
		return;

	local method = c$http$method;
	local uri = c$http$uri;

	if ( method != "POST" || uri != "/file/download" )
		return;

	# Check for "file" header and mark caldera_filename if suspicious.
	if ( ! c$http?$caldera_filename && name == "FILE" &&
	     value in suspicious_filenames )
		{
		c$http$caldera_filename = value;
		return;
		}

	# Check for "platform" header when suspicious filename already detected.
	if ( c$http?$caldera_filename && name == "PLATFORM" )
		{
		NOTICE([$conn=c, $note=Caldera::SuspiciousFileDownload,
			$msg=fmt("Caldera file download detected: file '%s', platform '%s', User-Agent '%s'",
				c$http$caldera_filename, value,
				c$http$user_agent),
			$identifier=c$uid]);
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( ! is_orig || ! c$http?$uri || ! c$http?$user_agent )
		return;

	if ( ! c$http?$method || c$http$method != "POST" )
		return;

	local user_agent = c$http$user_agent;
	local uri = c$http$uri;

	# Check for Caldera beacon activity.
	if ( uri == "/beacon" && /Go-http-client/ in user_agent )
		{
		NOTICE([$conn=c, $note=Caldera::C2Detected,
			$msg=fmt("Potential Sandcat beacon detected to %s with User-Agent '%s'",
				uri, user_agent),
			$identifier=c$uid]);
		return;
		}

	# Check for Ragdoll C2 activity.
	if ( uri == "/weather" && /python-requests\// in user_agent )
		{
		NOTICE([$conn=c, $note=Caldera::C2Detected,
			$msg=fmt("Potential Ragdoll C2 activity detected: URI '%s', User-Agent '%s'",
				uri, user_agent),
			$identifier=c$uid]);
		}
	}

function manx_c2_match(state: signature_state, data: string, transport: string, element: string): bool
	{
	local msg = fmt("Potential Manx %s C2 %s detected.", transport, element);
	NOTICE([$conn=state$conn, $note=Caldera::C2Detected, $msg=msg,
		$sub=data, $identifier=state$conn$uid]);
	return T;
	}

function manx_tcp_c2_match(state: signature_state, data: string): bool
	{
	return manx_c2_match(state, data, "TCP", "activity");
	}

function manx_udp_c2_match(state: signature_state, data: string): bool
	{
	return manx_c2_match(state, data, "UDP", "activity");
	}

function manx_udp_c2_reply_match(state: signature_state, data: string): bool
	{
	return manx_c2_match(state, data, "UDP", "reply");
	}
