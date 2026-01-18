# core/middleware/employer_required.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def employer_verified_required(view_func):
    """
    Allow access ONLY to verified employers.
    Pending employers are redirected to complete/upload profile,
    but do NOT redirect if already on those pages.
    Verified employers pass without interruption.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user

        # If not logged in
        if not user.is_authenticated:
            return redirect("login")

        profile = getattr(user, "profile", None)

        # Restrict only if user is an employer
        if profile and profile.role == "employer":
            company = getattr(user, "employer_company", None)

            # Allow access to complete/upload pages to prevent loops
            path_name = request.resolver_match.view_name
            if path_name in ["complete_employer_profile", "upload_company_docs"]:
                return view_func(request, *args, **kwargs)

            # No company profile → redirect to complete profile
            if not company:
                messages.warning(request, "Complete your company details first.")
                return redirect("complete_employer_profile")

            # Company exists but NOT verified → redirect to upload docs
            if not company.is_verified:
                messages.warning(
                    request,
                    "Your company is pending verification. Please upload documents."
                )
                return redirect("upload_company_docs")

            # Verified employer → allow access
            # (No redirect necessary)

        # Other roles → allow access
        return view_func(request, *args, **kwargs)

    return _wrapped_view
