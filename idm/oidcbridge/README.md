# Customer OIDC Adapter

This package is an opt-in OpenID Connect login adapter for the modified Cells Home build. It is disabled by default and does not alter WebDAV authentication; WebDAV continues to use Cells Personal Access Tokens.

## Current PoC Behavior

- Uses authorization code flow, state, nonce, and PKCE S256.
- Verifies the upstream ID token with issuer discovery, JWKS, audience, expiry, and nonce checks from `go-oidc`.
- Binds a Cells UUID deterministically to the exact `issuer + sub` pair.
- Creates or updates a Cells user and rejects login collisions instead of merging subjects by email.
- Issues a Cells authorization code and returns the browser to the existing `/auth/callback` flow.

Group synchronization, deprovisioning, account locking, PAT revocation, and real runtime acceptance remain separate unfinished slices.

## Configuration

Configuration lives under `services/pydio.web.customer-oidc`:

```yaml
services:
  pydio.web.customer-oidc:
    enabled: true
    issuerURL: https://id.example.com/realms/customer
    clientID: cells
    clientSecret: <Cells vault secret reference>
    redirectURL: https://files.example.com/auth/oidc/callback
    scopes: [openid, profile, email]
    usernameClaim: preferred_username
    emailClaim: email
    displayNameClaim: name
    groupsClaim: groups
    source: customer-oidc
    flowTTL: 5m
```

For isolated PoC execution, the client secret may instead be supplied through `CELLS_CUSTOMER_OIDC_CLIENT_SECRET`. Do not commit it or place it in non-secret configuration. HTTP issuer and redirect URLs are accepted only for loopback synthetic test environments; other endpoints must use HTTPS.
