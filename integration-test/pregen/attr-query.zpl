# oidc + zpr-attr/1 trusted-service interplay fixture (zipline#81, epic #72
# E1). oidc-file-interplay.zpl with the `file` decorator replaced by the
# networked `zpr-attr/1` attribute service:
#   - adapter1 is USER-ONLY: no bootstrap key; it authenticates through the
#     fake IdP (`google`, api = "oidc") as sub `user-a`.
#   - `zipline` (api = "zpr-attr/1") decorates that identity over HTTPS: the
#     reference zpr-attr-server vends dept plus the `contractor` tag, keyed
#     on user.sub.
#   - `allow contractor users to access Web.` is the ONLY statement
#     referencing a trusted-service attribute, and it references only
#     zipline's tag — so `google` survives compilation by the
#     identity-vendor retention rule (zipline#23), not by any attribute
#     reference.
#   - adapter2 stays device-only (bootstrap key) and provides Web.

define adapter as a device with zpr.adapter.cn.

define Node as adapter with zpr.adapter.cn:node.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

# Web is provided by adapter2's device CN; protocol/port in the .zplc match
# the existing ping connectivity check.
define Web as a service with device.zpr.adapter.cn:adapter2.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode as a service with device.zpr.adapter.cn:node.

# The interplay under test: `contractor` resolves through the zipline
# attribute service (contractor -> #user.contractor), keyed on the identity
# attribute user.sub that `google` mints.
allow contractor users to access Web.

# Fabric plumbing, unchanged from oidc-test.zpl.
allow Node to access PingableVs.
allow Vs to access PingableNode.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
