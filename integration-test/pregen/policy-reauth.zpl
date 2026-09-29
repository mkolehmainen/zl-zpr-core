# Policy-install re-authentication fixture (zipline#124, umbrella #118).
#
# The same one-node, two-adapter ping topology as oidc-test.zpl, but the two
# adapters are authenticated to exercise the two re-authentication arms a
# policy install must drive (zipline#123):
#   - adapter1 is USER-ONLY: no bootstrap key; identity is the OIDC `sub`
#     (user.oidc-subject) vouched by the fake-idp trusted service. Its
#     install-driven re-auth is the silent back-channel OIDC leg.
#   - adapter2 is DEVICE-ONLY: bootstrap RSA key, never logs a user in. Its
#     install-driven re-auth is the SS (bootstrap-signature) leg, and the
#     leg-3 revocation variant removes exactly this key.
#
# Unlike oidc-test.zpl there is no U2: adapter2 never authenticates a user,
# so its access to adapter1's service is a DEVICE rule. adapter1's user also
# reaches PingableVs so the leg-3 assertion "adapter1 unaffected" has a
# target that outlives adapter2's revocation.

define adapter as a device with zpr.adapter.cn.

define A2 as adapter with zpr.adapter.cn:adapter2.
define Node as adapter with zpr.adapter.cn:node.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

# The fake-IdP user adapter1 logs in as (the `sub` claim its IdP instance mints).
define U1 as users with oidc-subject:'user-a'.

# adapter1's pingable service is provided by the user identity — it has no
# device CN. adapter2's stays keyed on its device CN.
define A1Svc as a service with user.oidc-subject:'user-a'.
define A2Svc as a service with device.zpr.adapter.cn:adapter2.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode as a service with device.zpr.adapter.cn:node.

# The ping pair: adapter1's user reaches adapter2's service; adapter2's
# DEVICE reaches adapter1's service (no user on adapter2 by design).
allow U1 to access A2Svc.
allow A2 to access A1Svc.

# Leg-3 probe: adapter1 keeps a reachable target after adapter2 is revoked.
allow U1 to access PingableVs.

allow Node to access PingableVs.
allow Vs to access PingableNode.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
