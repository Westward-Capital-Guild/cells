#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

mkdir -p "$test_dir/bin"
cp "$script_dir/configure-oidc.sh" "$test_dir/configure-oidc.sh"
chmod 0755 "$test_dir/configure-oidc.sh"

cat > "$test_dir/bin/docker" <<'DOCKER'
#!/bin/sh
printf '%s\n' "$*" >> "$TEST_LOG"
case " $* " in
  *" exec -T "*) exit 0 ;;
  *" restart cells "*) cat >/dev/null; exit 0 ;;
  *) exit 1 ;;
esac
DOCKER
chmod 0755 "$test_dir/bin/docker"

PATH="$test_dir/bin:$PATH" TEST_DIR="$test_dir" TEST_LOG="$test_dir/docker.log" sh -s <<'REMOTE'
cd "$TEST_DIR"
./configure-oidc.sh
printf '%s\n' survived > after-configure
REMOTE

test "$(cat "$test_dir/after-configure")" = survived
grep -Fq 'pydio.web.customer-oidc issuerURL https://passport.denox-corp.com' "$test_dir/docker.log"
grep -Fq 'pydio.web.customer-oidc scopes openid profile email' "$test_dir/docker.log"
grep -Fq 'pydio.web.customer-oidc flowTTL 5m' "$test_dir/docker.log"
! grep -Eq 'customer-oidc .*"' "$test_dir/docker.log"
