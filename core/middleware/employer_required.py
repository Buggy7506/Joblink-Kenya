# core/middleware/employer_required.py

from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def employer_verified_required(view_func):
    """
    Restrict view access to verified employers only.
    Applicants, admins, and verified employers can pass.
    Pending or incomplete employers get redirected.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = request.user

        # If not logged in → send to login
        if not user.is_authenticated:
            return redirect("login")

        profile = getattr(user, "profile", None)

        # Only enforce if employer
        if profile and profile.role == "employer":
            company = getattr(user, "employercompany", None)

            # Employer did not create profile yet
            if not company:
                messages.warning(request, "Complete your company details first.")
                return redirect("complete_employer_profile")

            # Employer profile exists but not VERIFIED
            if company.status != "verified":
                messages.warning(
                    request,
                    "Your company is not verified yet. Upload verification details."
                )
                return redirect("upload_company_docs")

        # Otherwise allow access
        return view_func(request, *args, **kwargs)

    return _wrapped_view
