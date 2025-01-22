module Caldera;

export {
    redef enum Notice::Type += {
        Caldera::SandcatC2Detected,
        Caldera::RagdollC2Detected,
        Caldera::ManxTCPC2Detected,
        Caldera::ManxUDPC2Detected,
        Caldera::ManxUDPC2ReplyDetected,
        Caldera::SuspiciousFileDownload,
    };

    ## Global list of suspicious filenames to detect in file download traffic.
    global suspicious_filenames: set[string] = { "sandcat.go", "manx.go", "ragdoll.py" };
}

# Add custom field to the HTTP connection record.
redef record HTTP::Info += {
    caldera_filename: bool &default = F;  # Indicates if a suspicious filename was detected.
    caldera_filename_value: string &default = "";  
};

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) {
    if (!is_orig) return;  # Only process request headers.

    local method = c$http$method;
    local uri = c$http$uri;

    if (method != "POST" && uri != "/file/download")
		return;

    # Normalize header names to lowercase for consistency.
    local header_name = to_lower(name);

    # Check for the "file" header and mark caldera_filename if it's suspicious.
    if (c$http$caldera_filename == F && header_name == "file" && value in suspicious_filenames) {
        c$http$caldera_filename = T;
        c$http$caldera_filename_value = value;  # Store the matched filename in a custom field.
        return;
    }

    # Check for the "platform" header when a suspicious filename is already detected.
    if (c$http$caldera_filename == T && header_name == "platform") {
        NOTICE([
            $conn = c,
            $note = Caldera::SuspiciousFileDownload,
            $msg = fmt("Caldera file download detected: file '%s', platform '%s', User-Agent '%s'", 
                       c$http$caldera_filename_value, value, c$http$user_agent),
            $sub = "Caldera Suspicious File Download",
            $identifier=c$uid
        ]);
    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if (!is_orig) return;  # Only process request messages.

    local user_agent = c$http$user_agent;
    local method = c$http$method;
    local uri = c$http$uri;

    # Check for Caldera beacon activity.
    if (method == "POST" && uri == "/beacon") {
        if (|user_agent| > 0 && /Go-http-client/ in user_agent) {
            NOTICE([
                $conn = c,
                $note = Caldera::SandcatC2Detected,
                $msg = fmt("Potential beacon detected to %s with User-Agent '%s'", uri, user_agent),
                $identifier=c$uid
            ]);
            return;
        }
    }

    # Check for Ragdoll C2 activity.
    if (method == "POST" && uri == "/weather") {
        if (|user_agent| > 0 && /python-requests\// in user_agent) {
            NOTICE([
                $conn = c,
                $note = Caldera::RagdollC2Detected,
                $msg = fmt("Potential Ragdoll C2 activity detected: URI '%s', User-Agent '%s'", uri, user_agent),
                $identifier=c$uid
            ]);
        }
    }
}

function manx_c2_match(state: signature_state, data: string, note: Notice::Type, msg: string): bool &is_used
	{
    NOTICE([
        $conn = state$conn,
        $note = note,
        $msg = msg,
        $sub = data,
        $identifier = state$conn$uid
    ]);

    return T;
	}

function manx_tcp_c2_match(state: signature_state, data: string): bool &is_used
	{
    return manx_c2_match(state, data, Caldera::ManxTCPC2Detected, "Potential Manx TCP C2 activity detected.");
	}

function manx_udp_c2_match(state: signature_state, data: string): bool &is_used
	{
    return manx_c2_match(state, data, Caldera::ManxUDPC2Detected, "Potential Manx UDP C2 activity detected.");
	}

function manx_udp_c2_reply_match(state: signature_state, data: string): bool &is_used
	{
    return manx_c2_match(state, data, Caldera::ManxUDPC2ReplyDetected, "Potential Manx UDP C2 reply detected.");
	}
