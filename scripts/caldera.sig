signature caldera_manx_tcp_c2 {
    ip-proto == tcp
    payload /\{\"architecture\"[ ]*:[ ]*\"[^\"]*\"/
    payload /.*\"exe_name\"[ ]*:[ ]*\"manx\.go\"/
    payload /.*\"platform\"[ ]*:[ ]*\"[^\"]*\"/
    eval Caldera::manx_tcp_c2_match
}

signature caldera_manx_udp_c2 {
    ip-proto == udp
    payload /\{\"architecture\"[ ]*:[ ]*\"[^\"]*\"/
    payload /.*\"exe_name\"[ ]*:[ ]*\"manx\.go\"/
    payload /.*\"platform\"[ ]*:[ ]*\"[^\"]*\"/
    eval Caldera::manx_udp_c2_match
}

# The following can't use requires-reverse-signature because it happens on
# a different flow than the forward direction.
signature caldera_manx_udp_c2_reply {
    ip-proto == udp
    payload /roger/
    eval Caldera::manx_udp_c2_reply_match
}
