redef tcp_inactivity_timeout = 30sec;
redef udp_inactivity_timeout = 15sec;

# Without these @loads, Zeek only runs its base/ scripts — none of the
# Notice::Info types the WP5 Alert Exchange Format doc gives as reference
# examples (Scan::Port_Scan, Scan::Address_Scan, SSH::Password_Guessing,
# SSL::Invalid_Server_Cert) are policy/ scripts and are never active by
# default, so notice.log would stay empty of them without this.
#
# policy/misc/scan does not exist in Zeek 9.0.0 (confirmed on the actual
# sensor install — find/ls came back empty under policy/ and policy/misc/)
# — removed or restructured in this version, not a path typo. Commented
# out rather than guessing a replacement path; re-enable once we find
# where (or whether) scan detection lives in Zeek 9.
# @load policy/misc/scan
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssl/validate-certs

# Intel::Notice (doc §3.5) is intentionally not enabled here: it requires an
# operator-supplied threat-intel feed (redef Intel::read_files += {...}),
# which this project has none of. Add a feed and this @load to enable it:
# @load frameworks/intel/seen
