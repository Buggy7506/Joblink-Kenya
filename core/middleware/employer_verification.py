from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class EmployerVerificationMiddleware:
    """
    Block unverified employers from accessing restricted pages
    until documents are uploaded and approved.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        allowed_paths = [
            reverse("upload_company_docs"),
            reverse("logout"),
            reverse("dashboard"),
        ]

        # If not logged in, continue
        if not request.user.is_authenticated:
            return self.get_response(request)

        profile = getattr(request.user, "profile", None)

        # Only restrict employers
        if profile and profile.role == "employer":

            company = getattr(request.user, "company", None) \
                or getattr(request.user, "employercompany_set", None)

            # If company exists and pending/unverified
            if hasattr(request.user, "employercompany"):
                company = request.user.employercompany

                if company.status == "pending":
                    # Block all paths except upload + dashboard
                    if request.path not in allowed_paths:
                        messages.warning(
                            request,
                            "Upload company verification documents to unlock full access."
                        )
                        return redirect("upload_company_docs")

        return self.get_response(request)
