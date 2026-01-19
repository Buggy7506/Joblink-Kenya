# core/middleware/employer_verification.py

from django.shortcuts import redirect
from django.urls import resolve, Resolver404
from django.contrib import messages


class EmployerVerificationMiddleware:
    """
    Employer access control (loop-safe):
      - No company → force complete profile
      - Company not verified → force upload docs
      - Verified → unrestricted access
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
        # -----------------------------
        # Skip unauthenticated users
        # -----------------------------
        if not request.user.is_authenticated:
            return self.get_response(request)

        # -----------------------------
        # Skip admin/static/media early
        # -----------------------------
        path = request.path_info
        for prefix in self.SAFE_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        # -----------------------------
        # Safely resolve view name
        # -----------------------------
        try:
            current_view = resolve(path).url_name
        except Resolver404:
            return self.get_response(request)

        # -----------------------------
        # Skip safe views
        # -----------------------------
        if current_view in self.SAFE_VIEWS:
            return self.get_response(request)

        # -----------------------------
        # Only restrict employers
        # -----------------------------
        profile = getattr(request.user, "profile", None)
        if not profile or profile.role != "employer":
            return self.get_response(request)

        company = getattr(request.user, "employercompany", None)

        # --------------------------------------------------
        # Employer has NO company profile → redirect to complete profile
        # --------------------------------------------------
        if not company:
            if current_view != "complete_employer_profile":
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access."
                )
                return redirect("complete_employer_profile")
            return self.get_response(request)

        # --------------------------------------------------
        # Company exists but NOT verified → redirect to upload docs
        # --------------------------------------------------
        if not getattr(company, "is_verified", False):
            if current_view != "upload_company_docs":
                messages.warning(
                    request,
                    "Your company is pending verification. Upload documents."
                )
                return redirect("upload_company_docs")
            return self.get_response(request)

        # --------------------------------------------------
        # Verified employer → allow everything
        # --------------------------------------------------
        return self.get_response(request)
