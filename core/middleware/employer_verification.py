# core/middleware/employer_verification.py

from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages


class EmployerVerificationMiddleware:
    """
    Employer access control:
      - No company → force complete profile
      - Company not verified → force upload docs
      - Verified → unrestricted
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Let authentication middleware handle unauthenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        profile = getattr(request.user, "profile", None)
        if not profile or profile.role != "employer":
            return self.get_response(request)

        company = getattr(request.user, "employercompany", None)

        # Normalize paths
        current_path = request.path.rstrip("/")

        complete_profile_path = reverse("complete_employer_profile").rstrip("/")
        upload_docs_path = reverse("upload_company_docs").rstrip("/")
        dashboard_path = reverse("dashboard").rstrip("/")
        logout_path = reverse("logout").rstrip("/")

        allowed_paths = {
            complete_profile_path,
            upload_docs_path,
            dashboard_path,
            logout_path,
        }

        # --------------------------------------------------
        # Employer has NOT created a company profile
        # --------------------------------------------------
        if not company:
            if current_path != complete_profile_path:
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access."
                )
                return redirect("complete_employer_profile")

            return self.get_response(request)

        # --------------------------------------------------
        # Employer company exists but is NOT verified
        # --------------------------------------------------
        if company.status != "verified":
            if current_path != upload_docs_path:
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
