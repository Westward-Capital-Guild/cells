#!/bin/sh
set -eu

compose() {
  docker compose --env-file .env.stage -f compose.yaml -f docker-compose.denox-ingress.yml "$@"
}

set_config() {
  key="$1"
  value="$2"
  compose exec -T cells cells admin config set pydio.web.customer-oidc "$key" "$value"
}

set_config enabled true
set_config issuerURL '"https://passport.denox-corp.com"'
set_config clientID '"customer-file-platform"'
set_config redirectURL '"https://files.tools.denox-corp.com/auth/oidc/callback"'
set_config scopes '["openid","profile","email"]'
set_config usernameClaim '"preferred_username"'
set_config emailClaim '"email"'
set_config displayNameClaim '"name"'
set_config source '"denox-passport"'
set_config flowTTL '"5m"'

compose restart cells </dev/null
