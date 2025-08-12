Define AuthService as a service.
Define AuthSvcPing as a service with device.zpr.adapter.cn:'bas.zpr.org'.
Define NetAdmins   as users with color:blue.
Define WebService  as a service with user.bas_id:1234.

Allow zpr.adapter.cn: devices to access AuthService.

Allow color: users to access AuthSvcPing.

Allow color:green users to access WebServices.

Allow color:blue users to access VisaService.








