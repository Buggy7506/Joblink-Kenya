# core/middleware/employer_required.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def employer_verified_required(view_func):
    """
    Allow access ONLY to verified employers.
    Applicants, admins or non-employers are allowed normally.
    Pending employers get redirected to upload / complete.
    Verified employers pass without interruption.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user

        # If not logged in
        if not user.is_authenticated:
            return redirect("login")

        profile = getattr(user, "profile", None)

        # Restrict only if user is employer
        if profile and profile.role == "employer":
            company = getattr(user, "employer_company", None)

            # No company profile created
            if not company:
                messages.warning(request, "Complete your company details first.")
                return redirect("complete_employer_profile")

            # Company exists but NOT verified
            if company.status != "verified":
                messages.warning(
                    request,
                    "Your company is pending verification. Please upload documents."
                )
                return redirect("upload_company_docs")

            # 🎉 Fully verified employer → allow silently
            # (NO redirect to complete profile or docs)

        # Other roles → allow access
        return view_func(request, *args, **kwargs)

    return _wrapped_view
