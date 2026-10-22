#!/usr/bin/env bash
# Run the end-to-end tests (tests/e2e_kdc.rs) against a throwaway MIT KDC.
#
# Needs MIT Kerberos KDC tools (kdb5_util, kadmin.local, krb5kdc) and MIT kinit:
#   Debian/Ubuntu: krb5-kdc krb5-admin-server krb5-user
#   macOS:         brew install krb5 (put first on PATH automatically; Apple's own
#                  kinit is Heimdal's and does not read a password from stdin)
# The library under test is whatever kerbsec links: MIT on Linux, Apple's GSS.framework
# on macOS. Everything lives in a temp dir and is removed on exit (set KEEP=1 to keep
# it); the KDC listens on 127.0.0.1:8888.
#
# KERBSEC_E2E_CARGO_FLAGS overrides the cargo flags (default: --all-features), e.g.
#   KERBSEC_E2E_CARGO_FLAGS="--no-default-features --features dns" to test without IOV.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill "${kdc_pid:-}" 2>/dev/null || true; [ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT

cat > "$work/krb5.conf" <<CONF
[libdefaults]
 default_realm = TEST.LOCAL
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
[realms]
 TEST.LOCAL = {
  kdc = 127.0.0.1:8888
 }
[domain_realm]
 localhost = TEST.LOCAL
CONF
cat > "$work/kdc.conf" <<CONF
[kdcdefaults]
 kdc_ports = 8888
 kdc_tcp_ports = 8888
[realms]
 TEST.LOCAL = {
  database_name = $work/principal
  key_stash_file = $work/.k5
  max_life = 1d
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }
CONF

export KRB5_CONFIG="$work/krb5.conf" KRB5_KDC_PROFILE="$work/kdc.conf"
export KRB5CCNAME="FILE:$work/ccache" KRB5_KTNAME="$work/service.keytab"

if command -v brew >/dev/null 2>&1 && [ -d "$(brew --prefix krb5 2>/dev/null)" ]; then
  krb5_prefix="$(brew --prefix krb5)"
  PATH="$krb5_prefix/sbin:$krb5_prefix/bin:$PATH"
fi
PATH="$PATH:/usr/sbin"
kdb5_util create -s -r TEST.LOCAL -P masterpw >/dev/null
kadmin.local -q "addprinc -pw userpw user@TEST.LOCAL" >/dev/null
kadmin.local -q "addprinc -randkey host/localhost@TEST.LOCAL" >/dev/null
kadmin.local -q "ktadd -k $work/service.keytab host/localhost@TEST.LOCAL" >/dev/null

krb5kdc -n >"$work/kdc.log" 2>&1 &
kdc_pid=$!
for _ in $(seq 50); do
  (exec 3<>/dev/tcp/127.0.0.1/8888) 2>/dev/null && break
  kill -0 "$kdc_pid" 2>/dev/null || { cat "$work/kdc.log" >&2; exit 1; }
  sleep 0.1
done
echo userpw | kinit user@TEST.LOCAL

cd "$root"
# shellcheck disable=SC2086  # flags are intentionally word-split
cargo test ${KERBSEC_E2E_CARGO_FLAGS:---all-features} --test e2e_kdc -- --ignored --test-threads=1 "$@"
