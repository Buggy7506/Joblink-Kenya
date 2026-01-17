# core/middleware/complete_employer_profile_block.py

from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from .models import EmployerCompany

class PreventCompletedEmployerProfileAccess(MiddlewareMixin):
    """
    Middleware to prevent employers from accessing the complete-profile page
    after they have completed their company profile.
    """

    def process_request(self, request):
        # Only check for authenticated employers
        if (
            request.user.is_authenticated
            and getattr(request.user, "role", None) == "employer"
            and request.path.startswith("/employer/complete-profile")
        ):
            # Fetch employer company profile
            company = EmployerCompany.objects.filter(user=request.user).first()

            # If profile is complete, redirect to employer dashboard
            if company and company.company_name and company.business_email:
                return redirect("employer_control_panel")

        # Otherwise continue processing the request
        return None
