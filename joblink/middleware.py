from django.shortcuts import redirect

class PreventCompletedEmployerProfileAccess:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.user.is_authenticated
            and request.user.role == "employer"
            and request.path.startswith("/employer/complete-profile")
        ):
            company = EmployerCompany.objects.filter(user=request.user).first()

            if company and company.company_name and company.business_email:
                return redirect("employer_control_panel")

        return self.get_response(request)

class WwwAndHttpsRedirectMiddleware:
    """
    Redirects:
    1. stepper.dpdns.org -> www.stepper.dpdns.org
    2. http:// -> https://
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # IMPORTANT: Skip HEAD requests (Render health checks & shutdown)
        if request.method == "HEAD":
            return self.get_response(request)

        host = request.get_host()
        path = request.get_full_path()

        # Detect HTTPS correctly behind Render proxy
        is_secure = (
            request.is_secure()
            or request.META.get("HTTP_X_FORWARDED_PROTO") == "https"
        )

        desired_host = "www.stepper.dpdns.org"
        desired_scheme = "https"

        # Redirect only when necessary
        if host != desired_host or not is_secure:
            return redirect(
                f"{desired_scheme}://{desired_host}{path}",
                permanent=True
            )

        return self.get_response(request)
