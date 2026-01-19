# core/middleware/employer_verification.py

from django.shortcuts import redirect
from django.urls import resolve, Resolver404
from django.contrib import messages


class EmployerVerificationMiddleware:
    """
    Employer access control (loop-safe):
      - No company → force complete profile
      - Company not verified → force upload docs
      - Verified → unrestricted
    """

    SAFE_VIEWS = {
        "complete_employer_profile",
        "upload_company_docs",
        "dashboard",
        "login",
        "logout",
    }

    SAFE_PREFIXES = (
        "/admin",
        "/static",
        "/media",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip unauthenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip admin/static/media early
        path = request.path_info
        for prefix in self.SAFE_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        # Safely resolve view name
        try:
            current_view = resolve(path).url_name
        except Resolver404:
            return self.get_response(request)

        # Skip safe views
        if current_view in self.SAFE_VIEWS:
            return self.get_response(request)

        profile = getattr(request.user, "profile", None)
        if not profile or profile.role != "employer":
            return self.get_response(request)

        company = getattr(request.user, "employercompany", None)

        # --------------------------------------------------
        # Employer has NO company profile
        # --------------------------------------------------
        if not company:
            if not request.session.get("_company_redirected"):
                request.session["_company_redirected"] = True
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access."
                )
            return redirect("complete_employer_profile")

        # --------------------------------------------------
        # Employer company exists but is NOT verified
        # --------------------------------------------------
        if company.status != "verified":
            if not request.session.get("_verification_redirected"):
                request.session["_verification_redirected"] = True
                messages.warning(
                    request,
                    "Your company is pending verification. Upload documents."
                )
            return redirect("upload_company_docs")

        # --------------------------------------------------
        # Verified employer → allow everything
        # --------------------------------------------------
        return self.get_response(request)
