#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SIGNED_MESSAGE OPENDKIM_DNS_DATA" >&2
    exit 2
fi

message=$1
dns_data=$2
command -v opendkim >/dev/null
command -v rspamc >/dev/null

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
config="$temporary/opendkim.conf"
{
    echo "Mode v"
    echo "TestDNSData file:$dns_data"
    echo "Syslog no"
} > "$config"

opendkim_output="$temporary/opendkim.out"
if ! opendkim -x "$config" -t "$message" -vv >"$opendkim_output" 2>&1; then
    cat "$opendkim_output" >&2
    exit 1
fi
grep -Eqi '(signature (ok|verified|passes)|verification .* succeeded|dkim=pass)' "$opendkim_output"

rspamd_output="$temporary/rspamd.out"
rspamc --json "$message" > "$rspamd_output"
grep -q 'R_DKIM_ALLOW' "$rspamd_output"

echo "OpenDKIM and Rspamd independently accepted the DKIM signature"
