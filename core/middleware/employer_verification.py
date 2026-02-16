# core/middleware/employer_verification.py

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import Resolver404, resolve
from inspect import isawaitable


class EmployerVerificationMiddleware:
    """
    Employer access control (loop-safe):
      - No company or incomplete → force complete profile
      - Complete but not verified → force upload docs
      - Verified → unrestricted access

    Supports both sync and async request stacks.
    """

    async_capable = True
    sync_capable = True

    SAFE_VIEWS = {
        "complete_employer_profile",
        "upload_company_docs",
        "dashboard",
        "login",
        "logout",
    }

    SAFE_PREFIXES = (
        "/admin",
        "/static",
        "/media",
    )

    def __init__(self, get_response):
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)
            
    def __call__(self, request):
        if iscoroutinefunction(self.get_response):
            return self.__acall__(request)
        return self._process_request(request, request.user, self.get_response)

    async def __acall__(self, request):
        user = await request.auser() if hasattr(request, "auser") else request.user
        response = self._process_request(request, user)
        if response is not None:
            return response
        downstream_response = self.get_response(request)
        if isawaitable(downstream_response):
            return await downstream_response
        return downstream_response

    def _process_request(self, request, user, get_response=None):
        # -----------------------------
        # Skip unauthenticated users
        # -----------------------------
        if not user.is_authenticated:
            return get_response(request) if get_response else None

        path = request.path_info
        for prefix in self.SAFE_PREFIXES:
            if path.startswith(prefix):
                return get_response(request) if get_response else None

        # -----------------------------
        # Resolve view name safely
        # -----------------------------
        try:
            current_view = resolve(path).url_name
        except Resolver404:
            return get_response(request) if get_response else None

        if current_view in self.SAFE_VIEWS:
            return get_response(request) if get_response else None

        # -----------------------------
        # Only restrict employers
        # -----------------------------
        profile = getattr(user, "profile", None)
        user_role = getattr(user, "role", None)
        profile_role = getattr(profile, "role", None)

        # Guard against temporary role mismatch between CustomUser and Profile.
        is_employer = user_role == "employer" or profile_role == "employer"
        if not is_employer:
            return get_response(request) if get_response else None

        company = getattr(user, "employer_company", None)

        # --------------------------------------------------
        # No company or incomplete → force complete profile
        # --------------------------------------------------
        if not company or not company.is_complete:
            if current_view != "complete_employer_profile":
                messages.warning(
                    request,
                    "Complete your company profile to unlock full access.",
                )
                return redirect("complete_employer_profile")
            return get_response(request) if get_response else None

        # --------------------------------------------------
        # Company exists but NOT verified → force upload docs
        # --------------------------------------------------
        if not company.is_verified:
            if current_view != "upload_company_docs":
                messages.warning(
                    request,
                    "Your company is pending verification. Upload documents.",
                )
                return redirect("upload_company_docs")
            return get_response(request) if get_response else None

        # --------------------------------------------------
        # Verified employer → allow everything
        # --------------------------------------------------
        return get_response(request) if get_response else None
