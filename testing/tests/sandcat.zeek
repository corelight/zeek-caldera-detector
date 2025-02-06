# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -Cr $TRACES/sandcat.pcap $PACKAGE %INPUT >output
#
# Zeek 6 and newer populate the local_orig and local_resp columns by default,
# while earlier ones only do so after manual configuration. Filter out these
# columns to allow robust baseline comparison:
# @TEST-EXEC: cat conn.log | zeek-cut -m -n local_orig local_resp >conn.log.filtered
#
# Zeek 7.1 adds tracking of unhandled protocols which seems to change some notice uids.
# @TEST-EXEC: cat notice.log | zeek-cut -m -n uid >notice.log.filtered
# @TEST-EXEC: btest-diff notice.log.filtered
