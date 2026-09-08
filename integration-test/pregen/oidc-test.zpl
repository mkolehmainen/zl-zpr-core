# OIDC integration-test fixture (zipline#16, plan D5).
#
# Two adapters ping each other, but the actors are authenticated
# differently than in v4-1node-2actor-ping.zpl:
#   - adapter1 is USER-ONLY: no bootstrap key, identity is the OIDC `sub`
#     (user.oidc-subject) vouched by the fake-idp trusted service.
#   - adapter2 presents BOTH blobs: its bootstrap device key and a user
#     login.
# The node and the visa service adapter keep their device rules unchanged.

define adapter as a device with zpr.adapter.cn.

define A2 as adapter with zpr.adapter.cn:adapter2.
define Node as adapter with zpr.adapter.cn:node.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

# The two fake-IdP users (the `sub` claim each adapter's IdP instance mints).
define U1 as users with oidc-subject:'user-a'.
define U2 as users with oidc-subject:'user-b'.

# adapter1's pingable service is provided by the user identity — it has no
# device CN. adapter2's stays keyed on its device CN.
define A1Svc as a service with user.oidc-subject:'user-a'.
define A2Svc as a service with device.zpr.adapter.cn:adapter2.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode as a service with device.zpr.adapter.cn:node.

# User rules: adapter1's user reaches adapter2's service and vice versa.
allow U1 to access A2Svc.
allow U2 to access A1Svc.

allow Node to access PingableVs.
allow Vs to access PingableNode.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
