#!/bin/sh
set -eu

data_dir="${CELLS_DATA_DIR:-/var/cells/data}"
identity_file="$data_dir/.cells-storage-identity"

fs_type="$(stat -f -c %T "$data_dir")"
if [ "$fs_type" != "nfs" ]; then
  echo "refusing to start: $data_dir is $fs_type, expected nfs" >&2
  exit 70
fi

if [ ! -f "$identity_file" ]; then
  echo "refusing to start: NAS identity sentinel is missing" >&2
  exit 71
fi

actual_identity="$(tr -d '\r\n' < "$identity_file")"
if [ "$actual_identity" != "$CELLS_NAS_SENTINEL" ]; then
  echo "refusing to start: NAS identity sentinel does not match" >&2
  exit 72
fi

exec /opt/pydio/bin/docker-entrypoint.sh "$@"
