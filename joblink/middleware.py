from django.shortcuts import redirect

class WwwAndHttpsRedirectMiddleware:
    """
    Redirects:
    1. example.com -> www.example.com
    2. http:// -> https://
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host()
        scheme = 'https' if request.is_secure() else 'http'
        path = request.get_full_path()

        # Redirect non-www to www
        if host == "stepper.dpdns.org":
            return redirect(f"https://www.stepper.dpdns.org{path}", permanent=True)

        # Redirect http to https
        if scheme == 'http':
            return redirect(f"https://{host}{path}", permanent=True)

        return self.get_response(request)
