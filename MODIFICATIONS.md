# Modifications

This file provides the prominent modification notices required for this AGPL-covered fork. Dates use the Asia/Shanghai calendar date of the change.

## 2026-09-01: OIDC-Only Browser Login And Application Logout

Added:

- Opt-in boot configuration for an external identity login URL, button label,
  password-login mode, and application logout target.
- An OIDC-only login dialog mode that removes Cells username/password controls.
- Server-side rejection of browser `credentials` before password verification
  when the enabled customer OIDC service disables password login.
- Application logout sequencing that clears the Cells session before navigating
  to a configured application signed-out page.
- Focused Go and frontend tests covering safe redirect configuration, default
  compatibility, authorization-code pass-through, password rejection, and
  logout ordering/failure behavior.

WebDAV Personal Access Token authentication is not changed by this feature.
Customer-specific deployment, identity manifest, ingress, and runtime values are
kept outside this public platform repository.

## 2026-09-01: Customer OIDC Adapter PoC

Baseline: Pydio Cells Home `v5.0.2` / `1fc874469656deec2677ff6d2f487cf5c31dc3fd`.

Added:

- A customer-managed upstream OpenID Connect authorization-code flow with state, nonce, PKCE, bounded pending-flow storage, and no-cache/no-referrer responses.
- Deterministic Cells user identity derived from the exact OIDC `issuer + sub` pair.
- JIT Cells user creation and profile updates with explicit login-collision rejection.
- Exchange from a verified upstream identity into the existing Cells authorization-code/session flow.
- An opt-in Cells HTTP service at `/auth/oidc`; it is disabled unless explicitly configured.
- Focused tests for configuration security, identity mapping, replay prevention, user synchronization, PKCE, and Cells callback generation.
- A prominent About-dialog link to the immutable Corresponding Source release tag.

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
