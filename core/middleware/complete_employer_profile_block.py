# core/middleware/complete_employer_profile_block.py

from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from django.urls import reverse
from core.models import EmployerCompany

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
        ):
            current_path = request.path
            complete_profile_path = reverse("complete_employer_profile")  # Ensure your URL name
            dashboard_path = reverse("employer_control_panel")

            # Only redirect if accessing the complete-profile page
            if current_path.startswith(complete_profile_path):
                # Fetch employer company profile
                company = EmployerCompany.objects.filter(user=request.user).first()

                # If profile is complete and NOT already on dashboard, redirect safely
                if company and company.company_name and company.business_email:
                    # Avoid redirect loop
                    if current_path != dashboard_path:
                        return redirect(dashboard_path)

        # Otherwise continue processing the request
        return None
