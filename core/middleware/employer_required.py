# core/middleware/employer_required.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def employer_verified_required(view_func):
    """
    Allow access ONLY to verified employers.
    Pending employers are redirected to complete/upload profile,
    but do NOT redirect if already on those pages to prevent loops.
    Verified employers pass without interruption.
    Other roles (applicants, admins) pass normally.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user

        # Not logged in → redirect to login
        if not user.is_authenticated:
            return redirect("login")

        # Check if user has a profile
        profile = getattr(user, "profile", None)

        # Only restrict access if user is an employer
        if profile and getattr(profile, "role", None) == "employer":
            # Get associated company if exists
            company = getattr(user, "employer_company", None)

            # Get current view name to prevent redirect loops
            path_name = getattr(request.resolver_match, "view_name", None)
            if path_name in ["complete_employer_profile", "upload_company_docs"]:
                return view_func(request, *args, **kwargs)

            # No company profile → redirect to complete profile
            if not company:
                messages.warning(request, "Complete your company details first.")
                return redirect("complete_employer_profile")

            # Company exists but not verified → redirect to upload docs
            if not getattr(company, "is_verified", False):
                messages.warning(
                    request,
                    "Your company is pending verification. Please upload documents."
                )
                return redirect("upload_company_docs")

            # Verified employer → allow access (no redirect)

        # Other roles → allow access
        return view_func(request, *args, **kwargs)

    return _wrapped_view
