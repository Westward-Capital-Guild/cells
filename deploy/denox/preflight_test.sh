#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

mkdir -p "$test_dir/bin"
cp "$script_dir/preflight.sh" "$test_dir/preflight.sh"
chmod 0755 "$test_dir/preflight.sh"
printf '%s\n' 'CELLS_NAS_SENTINEL=test-sentinel' > "$test_dir/.env.stage"
chmod 0600 "$test_dir/.env.stage"

cat > "$test_dir/bin/docker" <<'DOCKER'
#!/bin/sh
case " $* " in
  *" network inspect "*|*" config -q "*) exit 0 ;;
  *" run "*) cat >/dev/null; printf '%s\n' 'test-sentinel' ;;
  *) exit 1 ;;
esac
DOCKER
chmod 0755 "$test_dir/bin/docker"

PATH="$test_dir/bin:$PATH" TEST_DIR="$test_dir" sh -s <<'REMOTE'
cd "$TEST_DIR"
./preflight.sh
printf '%s\n' survived > after-preflight
REMOTE

test "$(cat "$test_dir/after-preflight")" = survived
