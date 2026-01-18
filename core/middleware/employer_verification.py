# core/middleware/employer_verification.py

from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class EmployerVerificationMiddleware:
    """
    Restrict only employers:
      - No company → redirect to complete profile
      - Company not verified → redirect to upload docs
      - Verified → pass normally
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Not logged in → let login_required handle redirects
        if not request.user.is_authenticated:
            return self.get_response(request)

        profile = getattr(request.user, "profile", None)

        # Only target employers
        if profile and profile.role == "employer":

            # Fetch the company object if it exists
            company = getattr(request.user, "employercompany", None)

            # Normalize paths (remove trailing slash)
            current_path = request.path.rstrip('/')
            complete_profile_path = reverse("complete_employer_profile").rstrip('/')
            upload_docs_path = reverse("upload_company_docs").rstrip('/')
            dashboard_path = reverse("dashboard").rstrip('/')
            logout_path = reverse("logout").rstrip('/')

            allowed_paths = [complete_profile_path, upload_docs_path, dashboard_path, logout_path]

            # Employer with NO company created yet
            if not company and current_path != complete_profile_path:
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access."
                )
                return redirect("complete_employer_profile")

            # Company exists but NOT verified → redirect to docs upload
            if company and company.status != "verified" and current_path != upload_docs_path:
                messages.warning(
                    request,
                    "Your company is pending verification. Upload documents."
                )
                return redirect("upload_company_docs")

            # Verified employers skip restrictions entirely

        # Non-employers pass
        return self.get_response(request)
