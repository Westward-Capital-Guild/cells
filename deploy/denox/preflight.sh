#!/bin/sh
set -eu

compose() {
  docker compose --env-file .env.stage -f compose.yaml -f docker-compose.denox-ingress.yml "$@"
}

test -f .env.stage
test "$(stat -c %a .env.stage)" = "600"
docker network inspect denox_ingress >/dev/null
compose config -q

mkdir -p data/cells data/postgres

identity="$(compose run --rm --no-deps --entrypoint sh cells -c \
  'test "$(stat -f -c %T /var/cells/data)" = nfs && test -f /var/cells/data/.cells-storage-identity && tr -d "\r\n" < /var/cells/data/.cells-storage-identity' </dev/null)"

expected="$(sed -n 's/^CELLS_NAS_SENTINEL=//p' .env.stage)"
test -n "$expected"
test "$identity" = "$expected"
