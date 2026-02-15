# core/middleware/employer_verification.py

from django.shortcuts import redirect
from django.urls import resolve, Resolver404
from django.contrib import messages


class EmployerVerificationMiddleware:
    """
    Employer access control (loop-safe):
      - No company or incomplete → force complete profile
      - Complete but not verified → force upload docs
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

        path = request.path_info
        for prefix in self.SAFE_PREFIXES:
            if path.startswith(prefix):
                return self.get_response(request)

        # -----------------------------
        # Resolve view name safely
        # -----------------------------
        try:
            current_view = resolve(path).url_name
        except Resolver404:
            return self.get_response(request)

        if current_view in self.SAFE_VIEWS:
            return self.get_response(request)

        # -----------------------------
        # Only restrict employers
        # -----------------------------
        profile = getattr(request.user, "profile", None)
        user_role = getattr(request.user, "role", None)
        profile_role = getattr(profile, "role", None)

        # Guard against temporary role mismatch between CustomUser and Profile.
        is_employer = user_role == "employer" or profile_role == "employer"
        if not is_employer:
            return self.get_response(request)

        company = getattr(request.user, "employer_company", None)

        # --------------------------------------------------
        # No company or incomplete → force complete profile
        # --------------------------------------------------
        if not company or not company.is_complete:
            if current_view != "complete_employer_profile":
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access."
                )
                return redirect("complete_employer_profile")
            return self.get_response(request)

        # --------------------------------------------------
        # Company exists but NOT verified → force upload docs
        # --------------------------------------------------
        if not company.is_verified:
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
