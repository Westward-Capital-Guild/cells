# Corresponding Source Release Rules

This fork is licensed under the GNU Affero General Public License v3 or later. A public GitHub fork supports compliance but does not, by itself, complete the obligations for a deployed modified network service.

Every deployable release must satisfy all of the following:

1. Create an immutable source tag for the exact code used to build the release.
2. Keep the complete preferred source for modification, dependency declarations, build instructions, and deployment-relevant scripts in this repository.
3. Record `container image digest -> source tag -> source commit` in the release manifest.
4. Preserve the upstream copyright, license, no-warranty notices, and this fork's dated modification notices.
5. Display a prominent link in the running product that gives every remote user no-charge access to the exact release tag's Corresponding Source.
6. Do not publish secrets, customer configuration, customer identities, or customer files as source code.
7. Include these obligations in the customer operations handover because the customer becomes the network operator after delivery.

The existing About dialog loads `frontend/assets/gui.ajax/credits.md`, which contains the source offer for the current immutable release tag. Every later release must update that file to its own immutable source tag before building. A build whose About link does not resolve to its exact source is not releasable.

This first tag remains a development PoC and is not approved for customer production deployment because runtime identity acceptance is incomplete.

Recommended release metadata:

```text
upstream.version=v5.0.2
upstream.commit=1fc874469656deec2677ff6d2f487cf5c31dc3fd
source.repository=https://github.com/Westward-Capital-Guild/cells
source.tag=<immutable release tag>
source.commit=<release commit>
image.digest=<sha256 digest>
```
