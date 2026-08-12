# three adapters: they can ping each other
# Two nodes, one visa service: they can ping each other

define adapter as a device with zpr.adapter.cn.

define A1 as adapter with zpr.adapter.cn:adapter1.
define A2 as adapter with zpr.adapter.cn:adapter2.
define A3 as adapter with zpr.adapter.cn:adapter3.
define Node0 as adapter with zpr.adapter.cn:node.
define Node1 as adapter with zpr.adapter.cn:node1.
define Vs as adapter with zpr.adapter.cn:'vs.zpr'.

define A1Svc as a service with device.zpr.adapter.cn:adapter1.
define A2Svc as a service with device.zpr.adapter.cn:adapter2.
define A3Svc as a service with device.zpr.adapter.cn:adapter3.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableNode0 as a service with device.zpr.adapter.cn:node.
define PingableNode1 as a service with device.zpr.adapter.cn:node1.

allow A1 to access A2Svc.
allow A1 to access A3Svc.

allow A2 to access A1Svc.
allow A2 to access A3Svc.

allow A3 to access A1Svc.
allow A3 to access A2Svc.

allow Node0 to access PingableVs.
allow Node1 to access PingableVs.
allow Vs to access PingableNode0.
allow Vs to access PingableNode1.
allow PingableNode0 to access PingableNode1.
allow PingableNode1 to access PingableNode0.

# Admin access to VS
define VsAdmin as a device with zpr.adapter.cn:'client.zpr.org'.
allow VsAdmin to access VisaService.
