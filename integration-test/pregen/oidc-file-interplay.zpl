# oidc + file trusted-service interplay fixture (zipline#27, epic #22 finale).
#
# The zipline#22 policy (rationale: zl-zpr-dev-context/docs/VISA_SERVICE.md,
# "Design decisions"),
# adapted to the one-node OIDC topology (oidc-test.zpl):
#   - adapter1 is USER-ONLY: no bootstrap key; it authenticates through the
#     fake IdP (`google`, api = "oidc") as sub `user-a`.
#   - `happyfile` (api = "file") decorates that identity: its JSON is keyed
#     on user.sub and vends hair_color plus the `lazy` tag.
#   - `allow lazy users to access Web.` is the ONLY statement referencing a
#     trusted-service attribute, and it references only happyfile's tag —
#     so `google` survives compilation by the identity-vendor retention
#     rule (zipline#23), not by any attribute reference.
#   - adapter2 stays device-only (bootstrap key) and provides Web.

define adapter as a device with zpr.adapter.cn.

define Node as adapter with zpr.adapter.cn:node.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

# Web is provided by adapter2's device CN; protocol/port in the .zplc match
# the existing ping connectivity check.
define Web as a service with device.zpr.adapter.cn:adapter2.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode as a service with device.zpr.adapter.cn:node.

# The interplay under test: `lazy` resolves through the happyfile trusted
# service (lazy -> #user.lazy), keyed on the identity attribute user.sub
# that `google` mints.
allow lazy users to access Web.

# adapter1 must match a JOIN policy, or the visa service scrubs its requested
# ZPR address (fd5a:5052:8888::1:1, an unauthenticated claim) and assigns a
# dynamic fd5a:5052:adda:1::/64 one instead. The test's static tun0 setup keeps
# sourcing from fd5a:5052:8888::1:1, so the node would then deny every bind with
# "source address ... does not match actor address" (zipline#83). Join
# policies are minted per service provider, so give the user-a identity a
# service to provide (same trick as oidc-test.zpl's A1Svc). Vs is the client
# only so the service survives compilation; nothing in the test exercises it.
define UserASvc as a service with user.sub:'user-a'.
allow Vs to access UserASvc.

# Fabric plumbing, unchanged from oidc-test.zpl.
allow Node to access PingableVs.
allow Vs to access PingableNode.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
