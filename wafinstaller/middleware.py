from wafinstaller.helper.syslog import SyslogService, client_ip


class SyslogAuditMiddleware:
    """Send every successful state-changing request made by a panel user to syslog.

    Only the action, its URL parameters and the submitted field names/values are sent;
    secrets (passwords, OTP codes, tokens) are masked and file contents are omitted.
    Login/logout are reported by auth signals instead (see wafinstaller.signals).
    """

    METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    SKIP_ACTIONS = {"login", "verify_2fa", "logout"}
    SENSITIVE = ("password", "otp", "secret", "token", "csrf")
    OMIT_VALUE = ("content",)
    MAX_VALUE = 200

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        try:
            self._audit(request, response)
        except Exception:
            pass
        return response

    def _audit(self, request, response):
        if request.method not in self.METHODS or response.status_code >= 400:
            return
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return
        match = getattr(request, "resolver_match", None)
        action = match.url_name if match else ""
        if action in self.SKIP_ACTIONS:
            return
        SyslogService.audit(
            action or request.path,
            username=user.get_username(),
            ip=client_ip(request),
            method=request.method,
            path=request.path,
            params=dict(match.kwargs) if match else {},
            data=self._clean(request.POST),
            status=response.status_code,
        )

    def _clean(self, data):
        cleaned = {}
        for key in data.keys():
            lower = key.lower()
            if any(s in lower for s in self.SENSITIVE):
                if "csrf" not in lower:
                    cleaned[key] = "***"
                continue
            if any(s in lower for s in self.OMIT_VALUE):
                cleaned[key] = "<omitted>"
                continue
            values = data.getlist(key)
            value = values[0] if len(values) == 1 else values
            if isinstance(value, str) and len(value) > self.MAX_VALUE:
                value = value[: self.MAX_VALUE] + "..."
            cleaned[key] = value
        return cleaned
