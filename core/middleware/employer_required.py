# core/middleware/employer_required.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import resolve, Resolver404


def employer_verified_required(view_func):
    """
    Allow access ONLY to verified employers.
    Prevent redirect loops by checking BOTH view name and path.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user

        # Not logged in → redirect to login
        if not user.is_authenticated:
            return redirect("login")

        profile = getattr(user, "profile", None)

        # Only apply restrictions to employers
        if profile and getattr(profile, "role", None) == "employer":

            company = getattr(user, "employer_company", None)

            # Safely resolve current view
            try:
                current_view = resolve(request.path_info).url_name
            except Resolver404:
                current_view = None

            # Views that MUST NEVER redirect again
            SAFE_VIEWS = {
                "complete_employer_profile",
                "upload_company_docs",
                "login",
                "logout",
            }

            if current_view in SAFE_VIEWS:
                return view_func(request, *args, **kwargs)

            # No company → redirect ONCE
            if not company:
                messages.warning(
                    request,
                    "Complete your company details first."
                )
                return redirect("complete_employer_profile")

            # Company exists but not verified → redirect ONCE
            if not getattr(company, "is_verified", False):
                messages.warning(
                    request,
                    "Your company is pending verification. Please upload documents."
                )
                return redirect("upload_company_docs")

            # Verified employer → allow

        # Non-employers → allow
        return view_func(request, *args, **kwargs)

    return _wrapped_view
