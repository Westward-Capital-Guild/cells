#!/bin/sh
set -eu

public_base="https://files.tools.denox-corp.com"
passport_base="https://passport.denox-corp.com"

boot_code="$(curl -sS -o /dev/null -w '%{http_code}' "$public_base/a/frontend/bootconf")"
test "$boot_code" = "200"

location="$(curl -sS -o /dev/null -D - "$public_base/auth/oidc/login" | tr -d '\r' | sed -n 's/^[Ll]ocation: //p')"
case "$location" in
  "$passport_base"/oauth2/authorize*) ;;
  *) echo "unexpected OIDC redirect" >&2; exit 80 ;;
esac

printf '%s' "$location" | grep -q 'client_id=customer-file-platform'
printf '%s' "$location" | grep -q 'code_challenge_method=S256'

callback_code="$(curl -sS -o /dev/null -w '%{http_code}' "$public_base/auth/oidc/callback?state=invalid&code=invalid")"
test "$callback_code" = "400"

dav_code="$(curl -sS -o /dev/null -w '%{http_code}' -X PROPFIND "$public_base/dav/")"
case "$dav_code" in
  401|403) ;;
  *) echo "unexpected anonymous WebDAV status: $dav_code" >&2; exit 81 ;;
esac

printf 'bootconf=200 oidc_redirect=ok pkce=S256 invalid_callback=400 anonymous_webdav=%s\n' "$dav_code"
