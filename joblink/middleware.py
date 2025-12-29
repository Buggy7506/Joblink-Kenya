from django.shortcuts import redirect

class WwwAndHttpsRedirectMiddleware:
    """
    Redirects:
    1. stepper.dpdns.org -> www.stepper.dpdns.org
    2. http:// -> https://
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host()
        path = request.get_full_path()
        is_secure = request.is_secure() or request.META.get('HTTP_X_FORWARDED_PROTO') == 'https'

        # Desired host
        desired_host = 'www.stepper.dpdns.org'
        desired_scheme = 'https'

        # Check if host or scheme need to be fixed
        if host != desired_host or not is_secure:
            return redirect(f"{desired_scheme}://{desired_host}{path}", permanent=True)

        return self.get_response(request)
