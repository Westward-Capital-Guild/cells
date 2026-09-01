# Modifications

This file provides the prominent modification notices required for this AGPL-covered fork. Dates use the Asia/Shanghai calendar date of the change.

## 2026-09-01: Customer OIDC Adapter PoC

Baseline: Pydio Cells Home `v5.0.2` / `1fc874469656deec2677ff6d2f487cf5c31dc3fd`.

Added:

- A customer-managed upstream OpenID Connect authorization-code flow with state, nonce, PKCE, bounded pending-flow storage, and no-cache/no-referrer responses.
- Deterministic Cells user identity derived from the exact OIDC `issuer + sub` pair.
- JIT Cells user creation and profile updates with explicit login-collision rejection.
- Exchange from a verified upstream identity into the existing Cells authorization-code/session flow.
- An opt-in Cells HTTP service at `/auth/oidc`; it is disabled unless explicitly configured.
- Focused tests for configuration security, identity mapping, replay prevention, user synchronization, PKCE, and Cells callback generation.
- A prominent About-dialog link to the immutable `oidc-poc-v0.1.0` Corresponding Source tag.

Changed upstream files:

- `main.go`: loads the customer OIDC adapter service through one blank import.
- `README.md`: identifies this repository as an unofficial modified fork and links its source/compliance records.
- `frontend/assets/gui.ajax/credits.md`: displays the modified-distribution notice, license, and exact Corresponding Source link in the existing About dialog.

Not yet implemented or verified:

- Real IdP and real Cells end-to-end runtime acceptance.
- OIDC group to Cells role/ACL synchronization.
- IdP deprovisioning, Cells account lock, and PAT bulk revocation.
- Upgrade compatibility beyond the pinned `v5.0.2` baseline.

This PoC must not be described as production-ready or as having passed Gate 1 until those applicable acceptance cases have real runtime evidence.
