# =========================
# Django HTTP & shortcuts
# =========================
from django.shortcuts import render, redirect, get_object_or_404
from django.http import (
    HttpResponse,
    HttpResponseRedirect,
    FileResponse,
    JsonResponse,
    HttpResponseForbidden,
)
from django.urls import reverse, reverse_lazy
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST

# =========================
# Django authentication
# =========================
from django.contrib.auth import (
    login,
    logout,
    authenticate,
    update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import redirect_to_login
from django.contrib.auth.forms import PasswordResetForm
from django.contrib import messages

# =========================
# Django core utilities
# =========================
from django.conf import settings

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.files.base import ContentFile
from django.core.files.temp import NamedTemporaryFile
from django.core.paginator import Paginator
from django.db.models import Count, Q, F

# =========================
# Django templates & utils
# =========================
from django.template.loader import render_to_string
from django_ratelimit.decorators import ratelimit
from django_ratelimit.core import is_ratelimited
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from datetime import timedelta
from django.utils.text import slugify

# =========================
# Third-party libraries
# =========================
from weasyprint import HTML
import stripe
import requests
import cloudinary.uploader
from kombu.exceptions import OperationalError as KombuOperationalError
import secrets
import base64
import hashlib
import hmac
import json

# =========================
# Python standard library
# =========================
import os
import re
import urllib.parse
import logging
from pathlib import Path
from collections import namedtuple

# =========================
# Local app imports
# =========================
from .models import (
    JobCategory,
    JobAlert,
    ChatMessage,
    Application,
    Job,
    SkillResource,
    Resume,
    CVUpload,
    Profile,
    Notification,
    DeviceVerification,
    CustomUser,
    EmployerCompany,
)

from .forms import (
    EditProfileForm,
    ProfileForm,
    JobForm,
    EmployerCompanyForm,
    UnifiedAuthForm,
    CVUploadForm,
    CustomUserCreationForm,
    ChangeUsernamePasswordForm,
    AccountSettingsForm,
    CompanyDocumentForm,
)
from .utils import (
    generate_code,
    send_otp,
    get_client_ip,
    get_device_fingerprint,
    is_business_email,
    brevo_send_email,
    build_branded_email,
    otp_recently_sent,
    get_location_from_ip,
)

from .tasks import save_employer_document
from .email_backend import send_password_reset


logger = logging.getLogger(__name__)


def _normalize_next_url(request, next_url):
    """Return a safe local next URL or None."""
    if not next_url:
        return None

    if url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return next_url

    return None


def _redirect_to_next_or_dashboard(request):
    next_url = _normalize_next_url(request, request.session.pop("auth_next", None))
    return redirect(next_url or "dashboard")


def _get_effective_role(user):
    """Return a stable role, tolerating temporary user/profile mismatches."""
    profile = getattr(user, "profile", None)
    profile_role = getattr(profile, "role", None)
    user_role = getattr(user, "role", None)

    valid_roles = {"applicant", "employer", "admin"}
    profile_role = profile_role if profile_role in valid_roles else None
    user_role = user_role if user_role in valid_roles else None

    if profile_role and user_role and profile_role != user_role:
        # OAuth/account-creation can briefly leave profile.role at default.
        # Prefer the explicit role on CustomUser in that mismatch window.
        return user_role

    return profile_role or user_role

def robots_txt(request):
    content = """User-agent: *
Allow: /

Sitemap: https://www.stepper.dpdns.org/sitemap.xml
"""
    return HttpResponse(content, content_type="text/plain")

# -----------------------------------
# MAIN AUTH VIEW
# -----------------------------------
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def unified_auth_view(request):
    form = UnifiedAuthForm()
    ui_step = "email"
    is_new_user = False

    # Preserve ?next= across the entire auth flow
    next_url = _normalize_next_url(
        request,
        request.GET.get("next") or request.POST.get("next"),
    )
    
    if next_url:
        request.session["auth_next"] = next_url

    # ===============================
    # HELPERS
    # ===============================
    def resolve_user(identifier, channel):
        if not identifier:
            return None
        if channel == "email":
            return CustomUser.objects.filter(email__iexact=identifier).first()
        return CustomUser.objects.filter(phone=identifier).first()

    def derive_name_parts(channel, identifier):
        if not identifier:
            return ("User", "")
        if channel == "email":
            base = identifier.split("@")[0]
            parts = re.split(r"[._-]+", base)
            cleaned = [re.sub(r"\d+", "", part).strip() for part in parts]
            cleaned = [part for part in cleaned if part]
            first = cleaned[0].title() if cleaned else "User"
            last = cleaned[1].title() if len(cleaned) > 1 else ""
            return (first, last)
        last_digits = re.sub(r"\D", "", identifier)[-4:]
        fallback = f"User{last_digits}" if last_digits else "User"
        return (fallback, "")

    def derive_username(channel, identifier):
        first_name, _last_name = derive_name_parts(channel, identifier)
        base = re.sub(r"[^a-zA-Z0-9_]", "", first_name.lower()) or "user"
        username = base
        i = 1
    
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base}{i}"
            i += 1
    
        return username


    if request.method == "POST":
        action = request.POST.get("action")
        ui_step = request.POST.get("ui_step", "email")

        # ===============================
        # CONTEXT (SESSION SAFE)
        # ===============================
        if action in ["verify_code", "login_password", "magic_link", "resend_code"]:
            channel = request.session.get("otp_channel") or request.POST.get("channel", "email")
        else:
            channel = request.POST.get("channel", "email")

        raw_identifier = request.POST.get("identifier", "").strip()
        email = (
            raw_identifier.lower()
            if raw_identifier and channel == "email"
            else request.session.get("auth_email")
        )

        phone_raw = request.POST.get("phone", "").strip()
        phone = phone_raw if phone_raw else request.session.get("auth_phone")

        device_fingerprint = get_device_fingerprint(request)
        ip_address = get_client_ip(request)
        location = get_location_from_ip(ip_address)

        identifier = (
            email if action == "send_code" and channel == "email"
            else phone if action == "send_code"
            else request.session.get("auth_identifier")
        )

        # HARD GUARD
        if action in ["send_code", "magic_link"] and not identifier:
            messages.error(request, "Email or phone number is required.")
            return render(request, "auth.html", {"form": form, "ui_step": "email"})

        # ===============================
        # STEP 1 — SEND CODE
        # ===============================
        if action == "send_code":
            ui_step = "code"
        
            if channel == "email" and not email:
                messages.error(request, "Email is required.")
                return render(request, "auth.html", {"form": form, "ui_step": "email"})
            if channel == "email":
                try:
                    validate_email(email)
                except ValidationError:
                    messages.error(request, "Enter a valid email address.")
                    return render(request, "auth.html", {"form": form, "ui_step": "email"})
        
            if channel in ["sms", "whatsapp"] and not phone:
                messages.error(request, "Phone number is required.")
                return render(request, "auth.html", {"form": form, "ui_step": "email"})
        
            if otp_recently_sent(identifier, device_fingerprint):
                messages.warning(request, "Please wait before requesting another code.")
                return render(request, "auth.html", {"form": form, "ui_step": "code"})
        
            # 🔑 CRITICAL FIX — detect if user already exists
            user = resolve_user(identifier, channel)
            request.session["auth_user_exists"] = bool(user)
        
            # Invalidate old unused codes for this device
            DeviceVerification.objects.filter(
                identifier=identifier,
                device_fingerprint=device_fingerprint,
                is_used=False
            ).update(is_used=True)
        
            # Generate & store new OTP
            code = generate_code()
        
            DeviceVerification.objects.create(
                identifier=identifier,
                code=code,
                verified_via=channel,
                device_fingerprint=device_fingerprint,
                ip_address=ip_address,
                location=location,
            )
        
            # Send OTP
            send_otp(channel, identifier, code)
        
            # Persist auth context
            request.session.update({
                "auth_identifier": identifier,
                "auth_email": email,
                "auth_phone": phone,
                "otp_channel": channel,
            })
        
            messages.success(request, f"Verification code sent via {channel.upper()}.")
            return render(request, "auth.html", {"form": form, "ui_step": "code"})

        # ===============================
        # STEP 2 — VERIFY CODE
        # ===============================
        if action == "verify_code":
            code = request.POST.get("code")
            identifier = request.session.get("auth_identifier")
        
            if not code:
                messages.error(request, "Please enter the verification code.")
                return render(request, "auth.html", {"form": form, "ui_step": "code"})
        
            verification = DeviceVerification.objects.filter(
                identifier=identifier,
                code=code,
                verified_via=channel,
                device_fingerprint=device_fingerprint,
                is_used=False,
                created_at__gte=timezone.now() - timedelta(minutes=5),
            ).first()
        
            if not verification:
                messages.error(request, "Invalid or expired verification code.")
                return render(request, "auth.html", {"form": form, "ui_step": "code"})
        
            verification.is_used = True
            verification.save(update_fields=["is_used"])
        
            user = resolve_user(identifier, channel)
        
            # ✅ EXISTING USER → LOGIN IMMEDIATELY
            if user:
                login(request, user)
                verification.user = user
                verification.save(update_fields=["user"])
        
                for k in list(request.session.keys()):
                    if (k.startswith("auth_") and k != "auth_next") or k.startswith("otp_"):
                        del request.session[k]
        
                return _redirect_to_next_or_dashboard(request)
        
            # 🆕 NEW USER → PASSWORD SETUP
            request.session["otp_verified"] = True
            request.session["otp_verified_at"] = timezone.now().isoformat()
        
            # 🔥 CRITICAL: persist verified identity for password step
            request.session["auth_identifier"] = identifier
            request.session["otp_channel"] = channel
        
            return render(
                request,
                "auth.html",
                {
                    "form": form,
                    "ui_step": "password",
                    "is_new_user": True,
                }
            )

        # ===============================
        # STEP 2.5 — SWITCH TO PASSWORD 
        # ===============================
        if action == "switch_to_password":
        
            user_exists = request.session.get("auth_user_exists")
        
            # ✅ Existing user → go straight to password
            if user_exists:
                return render(
                    request,
                    "auth.html",
                    {
                        "form": form,
                        "ui_step": "password",
                        "is_new_user": False,
                    }
                )
        
            # 🆕 New user → OTP REQUIRED
            if not request.session.get("otp_verified"):
                messages.error(request, "Please verify the code to continue.")
                return render(
                    request,
                    "auth.html",
                    {
                        "form": form,
                        "ui_step": "code",
                    }
                )
        
            # 🆕 OTP verified → allow password
            return render(
                request,
                "auth.html",
                {
                    "form": form,
                    "ui_step": "password",
                    "is_new_user": True,
                }
            )

        # ===============================
        # STEP 2.75 — SET PASSWORD 
        # ===============================    
        if action == "set_password":
            if not request.session.get("otp_verified"):
                messages.error(request, "Please verify your code first.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "code"}
                )
        
            password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")
        
            if not password or password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "password", "is_new_user": True}
                )
        
            identifier = request.session.get("auth_identifier")
            channel = request.session.get("otp_channel")
            role = request.POST.get("role")
            if role not in ["applicant", "employer"]:
                messages.error(request, "Please select your role.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "password", "is_new_user": True}
                )
                
            first_name, last_name = derive_name_parts(channel, identifier)
            username = derive_username(channel, identifier)
        
            user = CustomUser.objects.create_user(
                username=username,
                email=identifier if channel == "email" else None,
                phone=identifier if channel != "email" else None,
                password=password,
                role=role,
                first_name=first_name,
                last_name=last_name,
            )
        
            Profile.objects.get_or_create(
                user=user,
                defaults={
                    "full_name": " ".join(part for part in [first_name, last_name] if part).strip() or username or identifier,
                    "role": role,
                }
            )
        
            login(request, user)
        
            # 🔑 CLEAN SESSION (VERY IMPORTANT)
            for k in list(request.session.keys()):
                if (k.startswith("auth_") and k != "auth_next") or k.startswith("otp_"):
                    del request.session[k]

            return _redirect_to_next_or_dashboard(request)

        # ===============================
        # STEP 3 — PASSWORD LOGIN (EXISTING USERS ONLY)
        # ===============================
        if action == "login_password":
            user_exists = request.session.get("auth_user_exists", False)
        
            # ❌ Block signup here — signup happens ONLY in set_password
            if not user_exists:
                messages.error(request, "Please create an account first.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "password", "is_new_user": True}
                )
        
            identifier = request.session.get("auth_identifier")
            password = request.POST.get("password")
        
            if not password:
                messages.error(request, "Password is required.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "password"}
                )
        
            user = resolve_user(identifier, channel)
        
            if not user or not user.check_password(password):
                messages.error(request, "Invalid credentials.")
                return render(
                    request,
                    "auth.html",
                    {"form": form, "ui_step": "password"}
                )
        
            login(request, user)
        
            # 🔑 Clean auth session state
            for k in list(request.session.keys()):
                if (k.startswith("auth_") and k != "auth_next") or k.startswith("otp_"):
                    del request.session[k]

            return _redirect_to_next_or_dashboard(request)
                
        # ===============================
        # RESEND CODE
        # ===============================
        if action == "resend_code":
            identifier = request.session.get("auth_identifier")
            channel = request.session.get("otp_channel") or channel

            if not identifier:
                messages.error(request, "Session expired. Please start again.")
                return render(request, "auth.html", {"form": form, "ui_step": "email"})

            if otp_recently_sent(identifier, device_fingerprint):
                messages.warning(request, "Please wait before requesting another code.")
                return render(request, "auth.html", {"form": form, "ui_step": "code"})

            DeviceVerification.objects.filter(
                identifier=identifier,
                device_fingerprint=device_fingerprint,
                is_used=False
            ).update(is_used=True)

            code = generate_code()

            DeviceVerification.objects.create(
                identifier=identifier,
                code=code,
                verified_via=channel,
                device_fingerprint=device_fingerprint,
                ip_address=ip_address,
                location=location,
            )

            send_otp(channel, identifier, code)
            messages.success(request, f"Code resent via {channel.upper()}.")
            return render(request, "auth.html", {"form": form, "ui_step": "code"})
            
        # ===============================
        # MAGIC LINK (EXISTING USERS ONLY)
        # ===============================
        if action == "magic_link":
            identifier = request.session.get("auth_identifier")

            if not identifier:
                messages.error(request, "Session expired. Please start again.")
                return render(request, "auth.html", {"form": form, "ui_step": "email"})

            user = resolve_user(identifier, channel)
            if not user:
                messages.error(
                    request,
                    "No account found. Please sign up with a password."
                )
                return render(request, "auth.html", {"form": form, "ui_step": "email"})

            if otp_recently_sent(identifier, device_fingerprint):
                messages.warning(request, "Please wait before requesting another code.")
                return render(request, "auth.html", {"form": form, "ui_step": "code"})

            DeviceVerification.objects.filter(
                identifier=identifier,
                device_fingerprint=device_fingerprint,
                is_used=False
            ).update(is_used=True)

            code = generate_code()

            DeviceVerification.objects.create(
                identifier=identifier,
                code=code,
                verified_via=channel,
                device_fingerprint=device_fingerprint,
                ip_address=ip_address,
                location=location,
                user=user,
            )

            send_otp(channel, identifier, code)
            messages.success(
                request,
                f"One-time login code sent via {channel.upper()}."
            )
            return render(request, "auth.html", {"form": form, "ui_step": "code"})

    return render(
        request,
        "auth.html",
        {
            "form": form,
            "ui_step": ui_step,
            "is_new_user": is_new_user,
            "next": request.session.get("auth_next", ""),
        }
    )

@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class CustomPasswordResetView(auth_views.PasswordResetView):
    template_name = "password_reset.html"
    form_class = PasswordResetForm
    success_url = reverse_lazy("password_reset_done")

    def form_valid(self, form):
        """
        Send password reset email via Brevo ONLY.
        Django email system is fully bypassed.
        """
        email = form.cleaned_data["email"]
        users = form.get_users(email)

        for user in users:
            send_password_reset(user, self.request)

        # DO NOT call super()
        return HttpResponseRedirect(self.success_url)


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class CustomPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = "password_reset_done.html"


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class CustomPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"


@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
class CustomPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = "password_reset_complete.html"

# Search + Filter + Pagination + Context
@ratelimit(key='ip', rate='30/m', block=True)
@csrf_protect
def available_jobs(request):
    search = request.GET.get("q", "").strip()
    sort = request.GET.get("sort", "").strip()

    # MULTI-SELECT FILTERS
    category_list = request.GET.getlist("category")
    location_list = request.GET.getlist("location")

    # BASE QUERYSET
    now = timezone.now()
    jobs = Job.objects.filter(is_active=True).filter(
        Q(expiry_date__isnull=True) | Q(expiry_date__gt=now)
    )

    # UNIFIED SEARCH: title OR category name OR location
    if search:
        jobs = jobs.filter(
            Q(title__icontains=search) |
            Q(category__name__icontains=search) |
            Q(location__icontains=search)
        )

    # FILTER BY MULTI-CATEGORY (by category name)
    if category_list:
        jobs = jobs.filter(category__name__in=category_list)

    # FILTER BY MULTI-LOCATION
    if location_list:
        jobs = jobs.filter(location__in=location_list)

    # SORTING
    if sort == "newest":
        jobs = jobs.order_by("-posted_on")
    elif sort == "expiry_asc":
        jobs = jobs.order_by("expiry_date")
    elif sort == "expiry_desc":
        jobs = jobs.order_by("-expiry_date")
    else:
        jobs = jobs.order_by("-id")  # default fallback

    # PAGINATION
    paginator = Paginator(jobs, 6)  # 6 jobs per page
    page_number = request.GET.get("page")
    jobs_page = paginator.get_page(page_number)

    # PREMIUM JOBS (top 3)
    premium_jobs = jobs.filter(is_premium=True)[:3]

    # UNIQUE FILTER OPTIONS FOR FRONTEND
    categories = JobCategory.objects.values_list("name", flat=True).distinct()
    locations = Job.objects.values_list("location", flat=True).distinct()

    # AJAX REQUEST: return just job cards
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return render(request, "job_cards.html", {
            "jobs": jobs_page,
        })

    # FULL PAGE LOAD
    return render(request, "job_list.html", {
        "jobs": jobs_page,
        "premium_jobs": premium_jobs,
        "search": search,
        "sort": sort,
        "category_list": category_list,
        "location_list": location_list,
        "categories": categories,
        "locations": locations,
    })
    
# =====================================================
# JOB CATEGORIES (EXTERNAL SOURCE – GitHub JSON)
# =====================================================
@ratelimit(key='ip', rate='30/m', block=True)
@csrf_exempt   # GET-only API
def api_job_categories(request):
    q = request.GET.get("q", "").strip().lower()

    # Keep a local fallback so suggestions always render even when providers fail.
    fallback_categories = [
        "Accounting", "Administration", "Agriculture", "Architecture", "Beauty & Wellness",
        "Customer Service", "Data & Analytics", "Design", "Driver", "Education",
        "Engineering", "Finance", "Healthcare", "Hospitality", "Human Resources",
        "Information Technology", "Legal", "Logistics", "Manufacturing", "Marketing",
        "Operations", "Procurement", "Project Management", "Sales", "Security",
        "Software Development", "Supply Chain", "Teaching", "Telecommunications", "Writing",
    ]

    provider_urls = [
        "https://api.trademe.co.nz/v1/categories/jobs.json",
    ]

    categories = set()

    for url in provider_urls:
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            payload = response.json()

            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        name = item.get("Category") or item.get("category") or item.get("name")
                    else:
                        name = item if isinstance(item, str) else None

                    if name:
                        categories.add(str(name).strip().title())
            elif isinstance(payload, dict):
                for key in ("categories", "data", "items", "job-titles", "job_titles"):
                    data = payload.get(key)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                name = item.get("Category") or item.get("category") or item.get("name")
                            else:
                                name = item if isinstance(item, str) else None
                            if name:
                                categories.add(str(name).strip().title())
        except Exception:
            continue

    if not categories:
        categories.update(fallback_categories)

    if q:
        filtered_categories = sorted({
            name for name in categories
            if name and q in name.lower()
        })[:15]
        if not filtered_categories:
            filtered_categories = sorted({
                name for name in fallback_categories
                if q in name.lower()
            })[:15]
    else:
        filtered_categories = fallback_categories[:15]
        
    return JsonResponse({"categories": filtered_categories})


# =====================================================
# LOCATIONS (OPENSTREETMAP / NOMINATIM)
# =====================================================
@ratelimit(key='ip', rate='30/m', block=True)
@csrf_exempt   # GET-only API
def api_locations(request):
    q = request.GET.get("q", "").strip()

    if len(q) < 3:
        return JsonResponse({"locations": []})

    url = "https://nominatim.openstreetmap.org/search"
    params = {
        "q": q,
        "format": "json",
        "addressdetails": 0,
        "limit": 8,
        "countrycodes": "ke"  # 🔹 Restrict results to Kenya
    }

    headers = {
        # REQUIRED by Nominatim usage policy
        "User-Agent": "Joblink Kenya/1.0 (support@stepper.dpdns.org)"
    }

    try:
        r = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=4
        )
        r.raise_for_status()

        data = r.json()

        locations = sorted({
            item.get("display_name")
            for item in data
            if item.get("display_name")
        })

        return JsonResponse({
            "locations": list(locations)
        })

    except Exception:
        return JsonResponse({
            "locations": []
        }, status=200)

# =====================================================
# JOB TITLES (EXTERNAL SOURCE – O*NET / COMMUNITY DATA)
# =====================================================
@ratelimit(key='ip', rate='30/m', block=True)
@csrf_exempt   # GET-only API
def api_job_titles(request):
    q = request.GET.get("q", "").strip().lower()

    if len(q) < 2:
        return JsonResponse({"titles": []})

    url = "https://raw.githubusercontent.com/jneidel/job-titles/master/job-titles.json"

    try:
        r = requests.get(url, timeout=4)
        r.raise_for_status()

        data = r.json()

        titles = sorted({
            title
            for title in data
            if isinstance(title, str)
            and q in title.lower()
        })[:15]

        return JsonResponse({
            "titles": titles
        })

    except Exception:
        return JsonResponse({
            "titles": []
        }, status=200)
        
# Ping Page
def ping(request):
    return HttpResponse("pong")
    
# Privacy Policy page
def privacy_policy(request):
    return render(request, "privacy_policy.html", {"now": timezone.now()})

# Terms of Service page
def terms_of_service(request):
    return render(request, "terms_of_service.html", {"now": timezone.now()})

# Learn More page
def learn_more(request):
    return render(request, "learn_more.html", {"now": timezone.now()})

# Cookies Policy page
def cookies_policy(request):
    return render(request, "cookies_policy.html", {"now": timezone.now()})

#About
def about(request):
    return render(request, "about.html", {"now": timezone.now()})

#Contact
def contact(request):
    return render(request, "contact.html", {"now": timezone.now()})

RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET")  # from Render environment

#@csrf_protect
# def choose_verification_method(request):
#     """
#     Let user choose a verification method (Email / WhatsApp / SMS) for OTP.
#     User is retrieved from session since the device is not verified yet.
#     """

#     # 🚫 Block access unless verification is pending
#     if not request.session.get("pending_verification"):
#         messages.error(request, "Unauthorized access.")
#         return redirect("unified_auth")

#     # 🔐 Ensure user is NOT authenticated (only if they are not in verification process)
#     if request.user.is_authenticated:
#         logout(request)

#     # Check if session is valid
#     user_id = request.session.get("verify_device_user_id")
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("unified_auth")

#     # Retrieve the user from the database
#     user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=user)

#     # Available methods for verification
#     options = []
#     if user.email:
#         options.append("email")

#     phone = getattr(profile, "phone", None)
#     if phone:
#         options.extend(["whatsapp", "sms"])

#     # If no methods are available, show an error
#     if not options:
#         messages.error(request, "No verification method available. Please contact support.")
#         return redirect("unified_auth")

#     # Handle POST request for method selection
#     if request.method == "POST":
#         method = request.POST.get("method")

#         # Ensure the selected method is valid
#         if method not in options:
#             messages.error(request, "Invalid verification method selected.")
#             return redirect("choose-verification-method")

#         # Save the selected method to session
#         request.session["verification_method"] = method

#         # Redirect to verify device page
#         return redirect("verify-device")

#     # Render the verification method selection page
#     return render(
#         request,
#         "choose_verification_method.html",
#         {
#             "user": user,
#             "profile": profile,
#             "options": options,
#             "selected_method": request.session.get("verification_method"),
#             "phone": phone,
#             "pending_verification": True,
#         },
#     )

#@csrf_protect
# def resend_device_code(request):
#     """
#     Handle the logic for resending the device verification OTP.
#     Rate-limits requests to prevent abuse.
#     """
#     # 1️⃣ Retrieve user from session
#     user_id = request.session.get('verify_device_user_id')
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("unified_auth")

#     user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=user)

#     # 2️⃣ Verify chosen method
#     method = request.session.get('verification_method', 'email')
#     if method not in ['email', 'whatsapp', 'sms']:
#         messages.error(request, "Invalid verification method.")
#         return redirect("verify-device")

#     # 3️⃣ Rate-limit OTP requests (30s cooldown)
#     last_otp_sent = request.session.get('last_otp_sent', None)
#     if last_otp_sent:
#         # Convert last_otp_sent back to datetime from string if it exists
#         last_otp_sent = datetime.strptime(last_otp_sent, "%Y-%m-%d %H:%M:%S")

#     now_time = datetime.now()
#     if last_otp_sent and now_time < last_otp_sent + timedelta(seconds=30):
#         remaining_time = (last_otp_sent + timedelta(seconds=30) - now_time).seconds
#         messages.error(request, f"Please wait {remaining_time} seconds before requesting a new OTP.")
#         return redirect("verify-device")

#     # 4️⃣ Generate OTP
#     otp_code = generate_code()  # your existing OTP generator function

#     device_fingerprint = request.session.get('device_fingerprint', 'unknown')
#     DeviceVerification.objects.update_or_create(
#         user=user,
#         device_fingerprint=device_fingerprint,
#         defaults={'code': otp_code, 'is_used': False, 'verified_via': method}
#     )

#     # 5️⃣ Send OTP
#     try:
#         if method == "email" and user.email:
#             send_mail(
#                 subject="Your JobLink Verification Code",
#                 message=f"Your verification code is: {otp_code}",
#                 from_email=settings.DEFAULT_FROM_EMAIL,
#                 recipient_list=[user.email],
#                 fail_silently=False,
#             )
#         elif method in ["sms", "whatsapp"]:
#             phone_number = profile.phone
#             if phone_number:
#                 # Replace print with actual SMS/WhatsApp sending logic
#                 print(f"OTP for {method.upper()} sent to {phone_number}: {otp_code}")
#             else:
#                 messages.error(request, f"No phone number available for {method.upper()}.")
#                 return redirect("verify-device")

#         # 6️⃣ Update last OTP sent time (store as string)
#         request.session['last_otp_sent'] = now_time.strftime("%Y-%m-%d %H:%M:%S")

#         messages.success(request, f"A new verification code has been sent via {method.upper()}.")
#     except Exception as e:
#         messages.error(request, f"Failed to send OTP: {str(e)}")

#     return redirect("verify-device")

#@csrf_protect
# def verify_device(request):
#     """
#     Handle OTP verification for new devices.
#     User is NOT logged in until device verification completes.
#     """

#     # Ensure user is logged out and session auth cleared
#     if request.user.is_authenticated:
#         logout(request)
#         request.session.flush()

#     user_id = request.session.get("verify_device_user_id")
#     if not user_id:
#         messages.error(request, "Session expired. Please login again.")
#         return redirect("unified_auth")

#     # Use a SAFE variable name (NOT 'user')
#     pending_user = get_object_or_404(CustomUser, id=user_id)
#     profile, _ = Profile.objects.get_or_create(user=pending_user)

#     device_hash = get_device_fingerprint(request)
#     ip = get_client_ip(request)
#     method = request.session.get("verification_method", "email")

#     verification = DeviceVerification.objects.filter(
#         user=pending_user,
#         device_fingerprint=device_hash,
#         is_used=False
#     ).order_by("-created_at").first()

#     # Generate & send OTP if none exists
#     if not verification:
#         code = generate_code()
#         verification = DeviceVerification.objects.create(
#             user=pending_user,
#             device_fingerprint=device_hash,
#             user_agent=request.META.get("HTTP_USER_AGENT", ""),
#             ip_address=ip,
#             code=code
#         )

#         try:
#             if method == "email" and pending_user.email:
#                 send_mail(
#                     subject="Your JobLink Verification Code",
#                     message=f"Your verification code is: {code}",
#                     from_email=settings.DEFAULT_FROM_EMAIL,
#                     recipient_list=[pending_user.email],
#                     fail_silently=False,
#                 )

#             elif method == "sms" and profile.phone:
#                 print(f"SMS OTP sent to {profile.phone}: {code}")

#             elif method == "whatsapp" and profile.phone:
#                 print(f"WhatsApp OTP sent to {profile.phone}: {code}")

#             else:
#                 messages.error(request, "No contact method available.")
#                 return redirect("verify-device")

#         except Exception:
#             messages.error(request, "Failed to send OTP.")
#             return redirect("verify-device")

#     # Validate OTP
#     if request.method == "POST":
#         entered_code = request.POST.get("otp", "").strip()

#         if verification and entered_code == verification.code:
#             verification.is_used = True
#             verification.verified_via = method
#             verification.save()

#             TrustedDevice.objects.update_or_create(
#                 user=pending_user,
#                 device_fingerprint=device_hash,
#                 defaults={
#                     "user_agent": request.META.get("HTTP_USER_AGENT", ""),
#                     "ip_address": ip,
#                     "verified": True,
#                 }
#             )

#             messages.success(
#                 request,
#                 "Device verified successfully. Please log in."
#             )
#             return redirect("unified_auth")

#         messages.error(request, "Invalid OTP. Please try again.")

#     # DO NOT pass `user` into template
#     return render(request, "verify_device.html", {
#         "method": method,
#         "profile": profile,
#         "pending_user": pending_user,  # ✅ SAFE
#     })

@csrf_protect
@login_required
@require_POST
def delete_cv(request):
    user = request.user
    # Get the latest CV for this user
    latest_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()

    if latest_cv and latest_cv.cv:
        # Delete from Cloudinary using public_id
        public_id = getattr(latest_cv.cv, 'public_id', None)
        if public_id:
            try:
                cloudinary.uploader.destroy(public_id)
            except Exception as e:
                # Optional: log the error
                print(f"Error deleting CV from Cloudinary: {e}")

        # Delete the model instance
        latest_cv.delete()

    return JsonResponse({'status': 'deleted'})

@csrf_protect
@login_required
def quick_profile_update(request):
    user = request.user
    DEFAULT_PIC = "https://res.cloudinary.com/dc6z1giw2/image/upload/v1754578015/jo2wvg1a0wgiava5be20.png"

    context = {
        "user": user,
        "skills": user.skills.split(",") if user.skills else [],
        "user_cv": CVUpload.objects.filter(applicant=user).order_by('-id').first(),
        "form_errors": {},
        "modal_type": None,
        "profile_picture_url": user.profile_pic.url if user.profile_pic else None,
    }

    if request.method == "POST":
        modal_type = request.POST.get("modal_type")
        context["modal_type"] = modal_type
        errors = {}

        # ---------- PHONE ----------
        if modal_type == "phone":
            phone = request.POST.get("phone", "").strip()
            if not phone:
                errors["phone"] = ["Phone number is required."]
            else:
                user.phone = phone

        # ---------- LOCATION ----------
        elif modal_type == "location":
            location = request.POST.get("location", "").strip()
            if not location:
                errors["location"] = ["Location is required."]
            else:
                user.location = location

        # ---------- EMAIL ----------
        elif modal_type == "email":
            email = request.POST.get("email", "").strip().lower()
            if not email:
                errors["email"] = ["Email is required."]
            else:
                try:
                    validate_email(email)
                except ValidationError:
                    errors["email"] = ["Enter a valid email address."]
                else:
                    exists = CustomUser.objects.filter(email__iexact=email).exclude(pk=user.pk).exists()
                    if exists:
                        errors["email"] = ["This email is already in use."]
                    else:
                        user.email = email
                        
        # ---------- SKILLS ----------
        elif modal_type == "skills":
            skills = request.POST.get("skills", "").strip()
            if not skills:
                errors["skills"] = ["Please add at least one skill."]
            else:
                user.skills = skills

        # ---------- CV UPLOAD ----------
        elif modal_type == "upload_cv":
            cv_file = request.FILES.get("upload_cv")
            if not cv_file:
                errors["upload_cv"] = ["Please upload a CV."]
            else:
                CVUpload.objects.create(applicant=user, cv=cv_file)
                context["user_cv"] = CVUpload.objects.filter(applicant=user).order_by('-id').first()

        # ---------- PROFILE PIC DELETE ----------
        elif modal_type == "profile_pic_delete":
            if user.profile_pic:
                try:
                    cloudinary.uploader.destroy(user.profile_pic.public_id)
                except Exception:
                    pass
                user.profile_pic = None
                user.save()
            return JsonResponse({"success": True, "url": DEFAULT_PIC})

        # ---------- PROFILE PIC UPLOAD ----------
        elif modal_type == "profile_pic":
            pic = request.FILES.get("profile_pic")
            if not pic:
                return JsonResponse({"success": False, "error": "No image selected."})
            else:
                user.profile_pic = pic
                user.save()
                return JsonResponse({"success": True, "url": user.profile_pic.url})

        # ---------- HANDLE VALIDATION ERRORS ----------
        if errors:
            context["form_errors"] = errors
            return render(request, "profile.html", context)

        # ---------- SAVE USER ----------
        user.save()

        # Redirect to profile after successful modal form submission
        return redirect("profile")

    # Fallback for GET requests
    return redirect("profile")

@csrf_protect
@login_required
def account_settings(request):
    """
    Handles username + password update
    """
    user = request.user

    if request.method == "POST":
        form = AccountSettingsForm(user=user, data=request.POST)

        if form.is_valid():
            form.save()
            update_session_auth_hash(request, user)  # keep user logged in
            messages.success(request, "Account details updated successfully.")
            return redirect("account_settings")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = AccountSettingsForm(user=user)

    return render(request, "change_username_password.html", {
        "form": form
    })

@csrf_protect
@login_required
def delete_account(request):
    """
    Requires password re-entry before deletion.
    """
    if request.method != "POST":
        return redirect(reverse("account_settings"))

    password = request.POST.get("password")
    user = authenticate(username=request.user.username, password=password)

    if user is None:
        messages.error(request, "Incorrect password. Account not deleted.")
        return redirect(f"{reverse('account_settings')}#danger")

    # Delete user and log out
    user.delete()
    logout(request)
    messages.success(request, "Your account has been permanently deleted.")
    return redirect(reverse("unified_auth"))

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def set_google_password(request):
    """
    Google OAuth users must set a password.
    """
    oauth_user = request.session.get('oauth_user')
    if not oauth_user:
        messages.error(request, "Session expired. Please login with Google again.")
        return redirect('unified_auth')

    # Pre-fill first name for template
    first_name = oauth_user.get('first_name', '')

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # -------------------------
        # 1️⃣ Validate inputs
        # -------------------------
        if not password or not confirm_password:
            messages.error(request, "Both password fields are required.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        # Strong password rules
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        if not re.search(r'[A-Z]', password):
            messages.error(request, "Password must contain an uppercase letter.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        if not re.search(r'\d', password):
            messages.error(request, "Password must contain a number.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        if not re.search(r'[@$!%*#?&]', password):
            messages.error(request, "Password must contain a special character.")
            return render(request, 'set_google_password.html', {'user': oauth_user})

        # -------------------------
        # 2️⃣ Prevent duplicate email
        # -------------------------
        email = oauth_user['email']
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists. Please log in.")
            return redirect('unified_auth')

        # -------------------------
        # 3️⃣ Create user
        # -------------------------
        last_name = oauth_user.get('last_name', '')
        role = request.session.get('oauth_role') or oauth_user.get('role')
        if role not in ['applicant', 'employer']:
            messages.error(request, "Please choose your role again.")
            return redirect('google_choose_role')

        # Username generation
        base_username = ''.join(e for e in first_name.lower() if e.isalnum()) or 'user'
        username = base_username
        counter = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = CustomUser.objects.create(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            role=role,
        )
        user.set_password(password)
        user.save()
        
        profile, created = Profile.objects.get_or_create(user=user)
        profile.role = role
        profile.save()

        # Optional: Save social profile picture (Google/Microsoft/Apple)
        picture_b64 = oauth_user.get('picture_b64')
        picture_url = oauth_user.get('picture')

        if picture_b64:
            try:
                image_bytes = base64.b64decode(picture_b64)
                picture_ext = oauth_user.get('picture_ext', 'jpg')
                provider = oauth_user.get('provider', 'oauth')
                user.profile_pic.save(
                    f"{username}_{provider}.{picture_ext}",
                    ContentFile(image_bytes),
                    save=True
                )
            except Exception:
                pass
        elif picture_url:
            try:
                response = requests.get(picture_url, timeout=5)
                if response.status_code == 200:
                    provider = oauth_user.get('provider', 'oauth')
                    user.profile_pic.save(
                        f"{username}_{provider}.jpg",
                        ContentFile(response.content),
                        save=True
                    )
            except Exception:
                pass

        # -------------------------
        # 4️⃣ Login + cleanup
        # -------------------------
        login(request, user)
        request.session.pop('oauth_user', None)
        request.session.pop('oauth_role', None)

        messages.success(request, "Account created successfully!")
        return _redirect_to_next_or_dashboard(request)

    # GET request
    return render(request, 'set_google_password.html', {'user': oauth_user})

# Google OAuth settings
GOOGLE_CLIENT_ID = '268485346186-pocroj4v0e6dhdufub2m4vaji0ts3ohj.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI = 'https://stepper.dpdns.org/google/callback/'
GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v1/userinfo'


def _sync_oauth_profile_picture(user, picture_url, provider='oauth'):
    """Download and persist an OAuth profile picture for a user."""
    if not picture_url:
        return False

    try:
        response = requests.get(picture_url, timeout=8)
        if response.status_code != 200:
            return False

        username = user.username or user.email or f"user_{user.id}"
        user.profile_pic.save(
            f"{slugify(username)}_{provider}.jpg",
            ContentFile(response.content),
            save=True,
        )
        return True
    except Exception as exc:
        logger.warning("OAuth profile picture sync failed for user %s: %s", user.pk, exc)
        return False

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def google_login(request):
    """Step 1: Redirect user to Google's OAuth 2.0 server"""
    next_url = _normalize_next_url(request, request.GET.get("next"))
    if next_url:
        request.session["auth_next"] = next_url

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent',
    }
    url = f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return redirect(url)

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def google_callback(request):
    """
    Handle Google OAuth callback.
    - Existing users: log in directly.
    - New users: store info in session and redirect to choose role.
    """
    code = request.GET.get('code')
    if not code:
        return redirect('unified_auth')  # cannot proceed without code

    # Exchange code for access token
    data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=data)
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    if not access_token:
        return redirect('unified_auth')  # cannot proceed without access token

    # Get user info from Google
    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get(GOOGLE_USERINFO_ENDPOINT, headers=headers)
    user_info = user_response.json()

    email = user_info.get('email')
    first_name = user_info.get('given_name', '')
    last_name = user_info.get('family_name', '')

    # Fallback: parse names from email if missing
    if not first_name or not last_name:
        local_part = email.split('@')[0]  # john.doe@gmail.com -> john.doe
        parts = local_part.split('.')
        first_name = first_name or parts[0].capitalize()
        last_name = last_name or (parts[1].capitalize() if len(parts) > 1 else '')

    if not email:
        return redirect('unified_auth')  # cannot proceed without email

    # Check if user already exists
    try:
        user = CustomUser.objects.get(email=email)
        _sync_oauth_profile_picture(user, user_info.get('picture'), provider='google')
        # Existing user: log in directly
        login(request, user)
        return _redirect_to_next_or_dashboard(request)
    except CustomUser.DoesNotExist:
        # New user: save info in session and redirect to role selection
        request.session['oauth_user'] = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'picture': user_info.get('picture'),
            'provider': 'google',
        }
        return redirect('google_choose_role')

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def google_choose_role(request):
    """
    Let user select role after Google OAuth.
    Only first-time users see this page.
    Role selection is stored in session for later account creation.
    Profile picture will be handled later in set_google_password.
    """
    user_data = request.session.get('oauth_user')
    if not user_data:
        messages.error(request, "Google login required first.")
        return redirect('unified_auth')

    email = user_data['email']

    # If user already exists and has a usable password, log in directly
    try:
        existing_user = CustomUser.objects.get(email=email)
        if existing_user.has_usable_password():
            login(request, existing_user)
            request.session.pop('oauth_user', None)
            return _redirect_to_next_or_dashboard(request)
    except CustomUser.DoesNotExist:
        pass

    if request.method == 'POST':
        role = request.POST.get('role')
        if role not in ['applicant', 'employer']:
            messages.error(request, "Please select a valid role.")
            return redirect('google_choose_role')

        # Store role in session for later account creation
        request.session['oauth_role'] = role
        user_data['role'] = role
        request.session['oauth_user'] = user_data
        
        return redirect('set_google_password')

    # GET request → render role selection template
    return render(request, 'google_role.html', {
        "oauth_user": user_data,
    })

def generate_apple_client_secret():
    """Return Apple client secret from environment configuration."""
    return os.getenv("APPLE_CLIENT_SECRET", "")


def decode_unverified_jwt_payload(token):
    """Decode JWT payload without signature verification for profile extraction."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_segment = parts[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
        return json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


APPLE_AUTH_ENDPOINT = "https://appleid.apple.com/auth/authorize"
APPLE_TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token"

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def apple_login(request):
    next_url = _normalize_next_url(request, request.GET.get("next"))
    if next_url:
        request.session["auth_next"] = next_url

    params = {
        "client_id": settings.APPLE_CLIENT_ID,
        "redirect_uri": settings.APPLE_REDIRECT_URI,
        "response_type": "code id_token",
        "scope": "name email",
        "response_mode": "form_post",
    }
    url = f"{APPLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return redirect(url)

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def apple_callback(request):
    code = request.POST.get("code")
    if not code:
        return redirect("unified_auth")

    # Exchange code for token (JWT client_secret required)
    client_secret = generate_apple_client_secret()
    if not client_secret:
        messages.error(request, "Apple login is not configured.")
        return redirect("unified_auth")

    token_response = requests.post(APPLE_TOKEN_ENDPOINT, data={
        "client_id": settings.APPLE_CLIENT_ID,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.APPLE_REDIRECT_URI,
    })

    token_data = token_response.json()
    id_token = token_data.get("id_token")

    if not id_token:
        return redirect("unified_auth")

    decoded = decode_unverified_jwt_payload(id_token)
    email = decoded.get("email")
    first_name = decoded.get("given_name", "")
    last_name = decoded.get("family_name", "")

    try:
        user = CustomUser.objects.get(email=email)
        login(request, user)
        return _redirect_to_next_or_dashboard(request)
    except CustomUser.DoesNotExist:
        request.session["oauth_user"] = {
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "provider": "apple",
        }
        return redirect("google_choose_role")
        
MICROSOFT_AUTH_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_ENDPOINT = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MICROSOFT_USERINFO_ENDPOINT = "https://graph.microsoft.com/v1.0/me"
MICROSOFT_PHOTO_ENDPOINT = "https://graph.microsoft.com/v1.0/me/photo/$value"

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def microsoft_login(request):
    next_url = _normalize_next_url(request, request.GET.get("next"))
    if next_url:
        request.session["auth_next"] = next_url

    params = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid email profile User.Read",
    }
    url = f"{MICROSOFT_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return redirect(url)

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def microsoft_callback(request):
    code = request.GET.get("code")
    if not code:
        return redirect("unified_auth")

    token_response = requests.post(MICROSOFT_TOKEN_ENDPOINT, data={
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
    })

    access_token = token_response.json().get("access_token")
    if not access_token:
        return redirect("unified_auth")

    headers = {"Authorization": f"Bearer {access_token}"}
    user_info = requests.get(MICROSOFT_USERINFO_ENDPOINT, headers=headers).json()

    email = user_info.get("mail") or user_info.get("userPrincipalName")
    first_name = user_info.get("givenName", "")
    last_name = user_info.get("surname", "")

    picture_b64 = None
    picture_ext = "jpg"
    try:
        photo_response = requests.get(MICROSOFT_PHOTO_ENDPOINT, headers=headers, timeout=10)
        if photo_response.status_code == 200 and photo_response.content:
            content_type = photo_response.headers.get("Content-Type", "image/jpeg")
            if "png" in content_type:
                picture_ext = "png"
            picture_b64 = base64.b64encode(photo_response.content).decode("utf-8")
    except Exception:
        pass

    try:
        user = CustomUser.objects.get(email=email)
        login(request, user)
        return _redirect_to_next_or_dashboard(request)
    except CustomUser.DoesNotExist:
        request.session["oauth_user"] = {
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "picture_b64": picture_b64,
            "picture_ext": picture_ext,
            "provider": "microsoft",
        }
        return redirect("google_choose_role")
    
# -----------------------------
# HELPER FUNCTIONS
# -----------------------------
def get_unread_messages(user):
    """
    Returns the count of unread chat messages for the given user.
    """
    return ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).count()

@csrf_protect
@login_required
def delete_message(request, msg_id):
    msg = get_object_or_404(ChatMessage, id=msg_id, sender=request.user)
    msg.delete()
    return JsonResponse({"status": "ok"})

@csrf_protect
@login_required
def edit_message(request, msg_id):
    msg = get_object_or_404(ChatMessage, id=msg_id, sender=request.user)
    new_text = request.POST.get("message")
    if new_text:
        msg.message = new_text
        msg.save()
    return JsonResponse({"status": "ok", "new_text": msg.message})


NotificationItem = namedtuple("NotificationItem", ["title", "message", "timestamp", "is_read", "url"])

@csrf_protect
@login_required
def notifications(request):
    user = request.user

    notifications = []

    # ---------------------------
    # Unread standard notifications
    # ---------------------------
    base_notifications = Notification.objects.filter(
        user=user, is_read=False
    ).order_by("-timestamp")

    for n in base_notifications:
        url = None

        # Detect job application notifications with job_id embedded in message
        match = re.search(r"job_id=(\d+)", n.message)
        if match:
            job_id = match.group(1)
            url = reverse("view_applicants") + f"?job_id={job_id}"

        notifications.append(
            NotificationItem(
                title=n.title,
                message=n.message.split("(job_id=")[0],  # strip hidden job_id part
                timestamp=n.timestamp,
                is_read=n.is_read,
                url=url,
            )
        )

    # ---------------------------
    # Unread chat messages
    # ---------------------------
    unread_chats = ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).order_by("-timestamp")

    for chat in unread_chats:
        if chat.application.applicant == user:
            chat_url = reverse("job_chat", args=[chat.application.id])
        else:
            chat_url = reverse("employer_chat", args=[chat.application.job.id]) + f"?app_id={chat.application.id}"

        notifications.append(
            NotificationItem(
                title=f"New message from {chat.sender.username}",
                message=chat.message,
                timestamp=chat.timestamp,
                is_read=False,
                url=chat_url,
            )
        )

    # ---------------------------
    # Sort by newest first
    # ---------------------------
    notifications.sort(key=lambda n: n.timestamp, reverse=True)

    total_unread = len(notifications)

    if not notifications:
        messages.info(request, "🔔 You don’t have any notifications yet.")

    context = {
        "notifications": notifications,
        "unread_count": total_unread,
        "role": getattr(user, "role", None),
        "title": "My Notifications",
    }
    return render(request, "notifications.html", context)

@csrf_protect
@login_required
def mark_all_read(request):
    """
    Marks all unread notifications and unread chat messages for the logged-in user as read.
    """
    user = request.user

    # Mark standard notifications as read
    Notification.objects.filter(user=user, is_read=False).update(is_read=True)

    # Mark unread chat messages as read
    ChatMessage.objects.filter(
        is_read=False
    ).filter(
        Q(application__applicant=user) & ~Q(sender=user) |
        Q(application__job__employer=user) & ~Q(sender=user)
    ).update(is_read=True)

    return redirect("notifications")  # back to notifications page

@csrf_protect
@login_required
def process_application(request, app_id):
    """
    Employer accepts or rejects a job application
    & email is sent automatically to the applicant.
    """
    application = get_object_or_404(Application, id=app_id)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'accept':
            application.status = 'accepted'
            subject = 'Job Application Approved ✅'
            message = f'Congratulations! Your application for {application.job.title} has been accepted.'

        else:  # reject
            application.status = 'rejected'
            subject = 'Job Application Result ❌'
            message = f'Sorry, your application for {application.job.title} has been rejected.'

        application.save()

        # send email to applicant
        brevo_send_email(
            subject=subject,
            recipient=application.applicant.email,
            html_content=build_branded_email(
                title=subject,
                body_html=f"""
                <p>{message}</p>
                <p style="color:#475569;font-size:14px">
                    If you have questions about this update, reply to this email.
                </p>
                """,
            ),
        )

    return redirect('dashboard')  # <— change to your employer dashboard URL name

#Home Page
@csrf_protect
def home(request):
    return render(request, 'home.html')

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def signup_view(request):
    """
    User signup view with Google reCAPTCHA verification.
    Supports Applicant & Employer signup with dynamic role-based fields.
    """

    # Default template variables
    role = "applicant"
    company_name = ""
    company_email = ""
    company_website = ""

    if request.method == "POST":
        recaptcha_response = request.POST.get("g-recaptcha-response")
        role = request.POST.get("role", "applicant").lower()

        company_name = request.POST.get("company_name", "").strip()
        company_email = request.POST.get("company_email", "").strip()
        company_website = request.POST.get("company_website", "").strip()

        # ============================================
        # FORCE EMAIL + USERNAME FOR EMPLOYERS
        # ============================================
        if role == "employer":
            request.POST._mutable = True

            if company_name:
                request.POST["username"] = slugify(company_name)[:150]

            if company_email:
                request.POST["email"] = company_email.lower()

            request.POST._mutable = False

        # Now bind form AFTER mutation
        form = CustomUserCreationForm(request.POST)

        # =========================
        # RECAPTCHA VERIFICATION
        # =========================
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, "signup.html", {
                "form": form,
                "role": role,
                "company_name": company_name,
                "company_email": company_email,
                "company_website": company_website
            })

        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET, "response": recaptcha_response}
        )

        if not r.json().get("success"):
            messages.error(request, "reCAPTCHA verification failed.")
            return render(request, "signup.html", {
                "form": form,
                "role": role,
                "company_name": company_name,
                "company_email": company_email,
                "company_website": company_website
            })

        # =========================
        # FORM VALIDATION
        # =========================
        if form.is_valid():

            # -------------------------
            # EMPLOYER STRICT CHECKS
            # -------------------------
            if role == "employer":

                if not company_name:
                    messages.error(request, "Company name is required.")
                    return render(request, "signup.html", {
                        "form": form,
                        "role": role,
                        "company_name": company_name,
                        "company_email": company_email,
                        "company_website": company_website
                    })

                if not company_email:
                    messages.error(request, "Business email is required.")
                    return render(request, "signup.html", {
                        "form": form,
                        "role": role,
                        "company_name": company_name,
                        "company_email": company_email,
                        "company_website": company_website
                    })

                if not is_business_email(company_email):
                    messages.error(
                        request,
                        "Please use a business/admin email address "
                        "(Gmail, Yahoo, etc. are not allowed)."
                    )
                    return render(request, "signup.html", {
                        "form": form,
                        "role": role,
                        "company_name": company_name,
                        "company_email": company_email,
                        "company_website": company_website
                    })

            # =========================
            # CREATE USER
            # =========================
            user = form.save()

            # =========================
            # ASSIGN ROLE DIRECTLY ON USER
            # =========================
            user.role = role if role in ["applicant", "employer"] else "applicant"
            user.save(update_fields=["role"])

            # =========================
            # ENSURE PROFILE EXISTS (no role stored here anymore)
            # =========================
            Profile.objects.get_or_create(user=user)

            # =========================
            # CREATE EMPLOYER COMPANY
            # =========================
            if user.role == "employer":
                EmployerCompany.objects.create(
                    user=user,
                    company_name=company_name,
                    business_email=company_email,
                    company_website=company_website,
                    status=EmployerCompany.STATUS_PENDING
                )

            # =========================
            # LOGIN USER
            # =========================
            login(request, user)

            # =========================
            # POST SIGNUP REDIRECTS
            # =========================
            if user.role == "employer":
                messages.info(
                    request,
                    "Your employer account is pending verification. "
                    "Upload your company documents to continue."
                )
                return redirect("upload_company_docs")

            messages.success(request, "Signup successful!")
            return redirect("dashboard")

        # Form invalid
        messages.error(request, "Please correct the errors below.")

    else:
        form = CustomUserCreationForm()

    return render(request, "signup.html", {
        "form": form,
        "role": role,
        "company_name": company_name,
        "company_email": company_email,
        "company_website": company_website
    })
    
# User Login
MAX_WRONG_ROLE_ATTEMPTS = 3
ROLE_LOCK_MINUTES = 30

@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def login_view(request):
    """
    Login view with device verification:
    - Username / Email / Phone
    - Device verification via Email / WhatsApp / SMS
    - Auto role detection
    - Role abuse protection
    - Employer approval enforcement
    """

    # ❌ Clear stale verification sessions (DEVICE VERIFICATION)
    # request.session.pop("verify_device_user_id", None)
    # request.session.pop("verification_method", None)
    # request.session.pop("pending_verification", None)

    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()
        password = request.POST.get('password', '').strip()
        selected_role = request.POST.get('role')  # applicant | employer
        recaptcha_response = request.POST.get('g-recaptcha-response')

        # 0️⃣ Verify Google reCAPTCHA
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, 'login.html')

        recaptcha_data = {
            'secret': RECAPTCHA_SECRET,
            'response': recaptcha_response
        }
        r = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data=recaptcha_data
        )
        result = r.json()

        if not result.get('success'):
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return render(request, 'login.html')

        # 1️⃣ Find user
        try:
            user_obj = CustomUser.objects.get(
                Q(username=identifier) |
                Q(email=identifier) |
                Q(phone=identifier)
            )
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # Ensure profile exists for lock tracking
        profile, _ = Profile.objects.get_or_create(user=user_obj)

        # 🛡 ROLE LOCK CHECK
        if profile.role_lock_until and profile.role_lock_until > timezone.now():
            minutes = int(
                (profile.role_lock_until - timezone.now()).total_seconds() / 60
            )
            messages.error(
                request,
                f"Account locked due to repeated wrong role attempts. "
                f"Try again in {minutes} minutes."
            )
            return render(request, 'login.html')

        # 2️⃣ Google users → force password setup
        if not user_obj.has_usable_password():
            request.session["set_password_user_id"] = user_obj.id
            messages.info(request, "Please set your password to continue.")
            return redirect("set_google_password")

        # 3️⃣ Authenticate credentials
        user = authenticate(
            request,
            username=user_obj.username,
            password=password
        )

        if user is None:
            messages.error(request, "Invalid credentials")
            return render(request, 'login.html')

        # ==========================
        # ✅ LOGIN USER FIRST (CRITICAL FIX)
        # ==========================
        login(request, user)

        # ❌ DEVICE TRUST CHECK (DISABLED)
        # device_hash = get_device_fingerprint(request)
        # device = TrustedDevice.objects.filter(
        #     user=user,
        #     device_fingerprint=device_hash,
        #     verified=True
        # ).first()

        # ❌ UNTRUSTED DEVICE VERIFICATION FLOW (DISABLED)
        # if not device:
        #     ip = get_client_ip(request)
        #
        #     DeviceVerification.objects.get_or_create(
        #         user=user,
        #         device_fingerprint=device_hash,
        #         is_used=False,
        #         defaults={
        #             "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        #             "ip_address": ip,
        #             "code": generate_code(),
        #         }
        #     )
        #
        #     logout(request)
        #
        #     request.session["verify_device_user_id"] = user.id
        #     request.session["pending_verification"] = True
        #
        #     return redirect("choose-verification-method")

        # ==========================
        # 🧠 AUTO-DETECT REAL ROLE (NOW FROM USER)
        # ==========================
        actual_role = user_obj.role

        # 🛡 WRONG ROLE ATTEMPT
        if selected_role and selected_role != actual_role:
            profile.role_failed_attempts += 1

            if profile.role_failed_attempts >= MAX_WRONG_ROLE_ATTEMPTS:
                profile.role_lock_until = timezone.now() + timedelta(minutes=ROLE_LOCK_MINUTES)
                profile.role_failed_attempts = 0
                profile.save()

                messages.error(
                    request,
                    "Too many wrong role attempts. Account temporarily locked."
                )
                return render(request, 'login.html')

            profile.save()
            messages.error(
                request,
                f"This account is registered as {actual_role.capitalize()}."
            )
            return render(request, 'login.html')

        # ✅ RESET ROLE ATTEMPTS
        profile.role_failed_attempts = 0
        profile.role_lock_until = None
        profile.save()

        # ==========================
        # EMPLOYER SELF-VERIFICATION CHECK
        # ==========================
        if actual_role == "employer":
            company, created = EmployerCompany.objects.get_or_create(user=user)

            # Newly created → auto_verify will run in save()
            if created:
                company.save()

            # If missing data → force setup page
            if not company.company_name or not company.business_email:
                return redirect("complete_employer_profile")

            # Auto-reverify if pending (fix silently)
            if company.status == EmployerCompany.STATUS_PENDING:
                company.save()

        # ❌ Cleanup verification flags (DEVICE VERIFICATION)
        # request.session.pop("pending_verification", None)

        # ==========================
        # ROLE-AWARE REDIRECT
        # ==========================

        # Admin
        if user.is_superuser:
            return redirect("admin_dashboard")

        # Employer
        if actual_role == "employer":
            return redirect("employer_control_panel")

        # Applicant
        return redirect("dashboard")

    return render(request, 'login.html')
    
@csrf_protect
@login_required
def complete_employer_profile(request):
    user = request.user

    
    effective_role = _get_effective_role(user)
    if effective_role != "employer":
        messages.error(request, "Only employers can access this page.")
        return redirect("dashboard")

    company = EmployerCompany.objects.filter(user=user).first()

    if company and company.is_verified:
        messages.info(request, "Your company is already verified.")
        return redirect("dashboard")

    if request.method == "POST":
        company_form = EmployerCompanyForm(request.POST, instance=company)
        doc_form = CompanyDocumentForm(
            {"document_type": request.POST.get("document_type")},
            {"file": request.FILES.get("file")},
        )
        
        if not company_form.is_valid() or not doc_form.is_valid():
            if not company_form.is_valid():
                messages.error(request, "Please correct the company profile errors below.")
            if not doc_form.is_valid():
                messages.error(request, "Please correct the document upload errors below.")
            return render(
                request,
                "complete_profile.html",
                {
                    "form": company_form,
                    "doc_form": doc_form,
                    "company": company,
                    "documents": company.documents.all() if company else [],
                },
                status=400,
            )

        company = company_form.save(commit=False)
        company.user = user
        company.save()

        uploaded_file = request.FILES.get("file")
        temp_dir = Path(settings.MEDIA_ROOT) / "temp_uploads"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / uploaded_file.name

        with open(temp_path, "wb+") as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        try:
            save_employer_document.delay(
                user.id,
                str(temp_path),
                doc_form.cleaned_data["document_type"],
            )
        except KombuOperationalError:
            save_employer_document.apply(
                args=(
                    user.id,
                    str(temp_path),
                    doc_form.cleaned_data["document_type"],
                )
            )

        company.refresh_from_db()
        if company.is_verified:
            messages.success(request, "Company verified successfully.")
            return redirect("dashboard")

        messages.success(request, "Profile saved. Verification is in progress.")
        return redirect("complete_employer_profile")

    company_form = EmployerCompanyForm(instance=company)
    doc_form = CompanyDocumentForm()

    return render(
        request,
        "complete_profile.html",
        {
            "form": company_form,
            "doc_form": doc_form,
            "company": company,
            "documents": company.documents.all() if company else [],
        },
    )
    
#User Logout
@csrf_protect
def logout_view(request):
    logout(request)
    return redirect('logout_success')

# Logout success message
@csrf_protect
def logout_success(request):
    return render(request, 'logout_success.html')

# Dashboard
@csrf_protect
@login_required
def dashboard(request):
    user = request.user

    # Count unread messages + notifications
    unread_messages_count = get_unread_messages(user)
    notifications_count = Notification.objects.filter(user=user, is_read=False).count()
    total_notifications = unread_messages_count + notifications_count

    user_role = getattr(user, "role", None)
    effective_role = _get_effective_role(user)

    # Admin dashboard
    if user.is_superuser or user_role == "admin":
        return redirect("admin_dashboard")

    # Applicant dashboard
    if effective_role == "applicant":
        applications = Application.objects.filter(applicant=user)
        premium_jobs = applications.filter(job__is_premium=True).count()
        deleted_apps_count = applications.filter(is_deleted=True).count()

        return render(request, "applicant_dashboard.html", {
            "applications": applications,
            "premium_jobs": premium_jobs,
            "deleted_apps_count": deleted_apps_count,
            "notifications_count": total_notifications,
        })

    # Employer dashboard
    elif effective_role == "employer":
        # Check employer verification
        company = getattr(user, "employer_company", None)
        if not company or not company.is_verified:
            messages.warning(request, "⏳ Please verify your company to unlock full employer access.")
            return redirect("upload_company_docs")  # Send to docs upload

        posted_jobs_count = Job.objects.filter(employer=user).count()
        active_jobs = Job.objects.filter(employer=user, is_active=True).count()
        applicants_count = Application.objects.filter(
            job__employer=user,
            is_deleted=False
        ).count()

        return render(request, "employer_dashboard.html", {
            "posted_jobs_count": posted_jobs_count,
            "active_jobs": active_jobs,
            "applicants_count": applicants_count,
            "notifications_count": total_notifications,
        })

    # Fallback → unknown role
    return redirect("unified_auth")

@csrf_protect
@login_required
def upload_company_docs(request):
    """Use the same non-JSON form flow as complete_employer_profile."""
    return complete_employer_profile(request)

@csrf_protect
@login_required
def profile_view(request):
    user = request.user  # CustomUser instance

    if request.method == "POST":
        form = ProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()

            # Handle CV upload if a new file is provided
            uploaded_cv = request.FILES.get('upload_cv')
            if uploaded_cv:
                CVUpload.objects.create(applicant=user, cv=uploaded_cv)

            return redirect('profile')  # Reload page to reflect updates
    else:
        form = ProfileForm(instance=user)

    # Get the latest CV for this user
    latest_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()
    cv_filename = os.path.basename(latest_cv.cv.url) if latest_cv and latest_cv.cv else None

    # Convert skills string to a list (comma-separated)
    skills_list = [skill.strip() for skill in user.skills.split(',')] if user.skills else []

    context = {
        'user': user,
        'user_cv': latest_cv,
        'cv_filename': cv_filename,                  # Pass filename for template display
        'skills': skills_list,
        'profile_picture_url': user.profile_pic.url if user.profile_pic else None,
        'form': form,
    }

    # Choose template based on user role
    template_name = 'employer_profile.html' if user.role == 'employer' else 'profile.html'
    return render(request, template_name, context)
    
@csrf_protect
@login_required
def view_posted_jobs(request):
    if not request.user.is_superuser and _get_effective_role(request.user) != 'employer':
        messages.error(request, "❌ Only employers can access posted jobs.")
        return redirect('dashboard')
    jobs = Job.objects.all().order_by('-posted_on')
    posted_jobs = Job.objects.filter(employer=request.user).order_by('-posted_on')
    posted_jobs_count = posted_jobs.count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    if request.method == 'POST':
        job_id = request.POST.get('job_id')
        if job_id:
            job = get_object_or_404(Job, id=job_id, employer=request.user)
            job.delete()
            messages.success(request, f"Job '{job.title}' deleted successfully.")
            return redirect('view_posted_jobs')
        else:
            messages.error(request, "Job ID is missing.")
    return render(request, 'view_posted_jobs.html', {
        'jobs': jobs,
        'posted_jobs': posted_jobs,
        'posted_jobs_count': posted_jobs_count,
        'active_jobs': active_jobs
    })

@csrf_protect
@login_required
def view_applicants(request):
    if not request.user.is_superuser and _get_effective_role(request.user) != "employer":
        messages.error(request, "❌ Only employers can access applicants.")
        return redirect("dashboard")

    job_id = request.GET.get("job_id")  # Check if employer is filtering for a specific job

    if job_id:
        # Show only applicants for the specific job, excluding soft-deleted for employer
        applicants = Application.objects.filter(
            job__id=job_id,
            job__employer=request.user,
            is_deleted_for_employer=False  # hide soft-deleted applications
        ).select_related("job", "applicant")

        applicants_count = applicants.count()
        jobs = Job.objects.filter(id=job_id, employer=request.user)  # just that job
    else:
        # Show applicants for ALL jobs posted by this employer
        jobs = Job.objects.filter(employer=request.user)
        applicants = Application.objects.filter(
            job__in=jobs,
            is_deleted_for_employer=False  # hide soft-deleted applications
        ).select_related("job", "applicant")
        applicants_count = applicants.count()

    return render(request, "view_applicants.html", {
        "jobs": jobs,
        "applicants": applicants,
        "applicants_count": applicants_count,
        "job_id": job_id,  # useful in template
    })

@csrf_protect
@login_required
def employer_control_panel_view(request):
    if not request.user.is_superuser and _get_effective_role(request.user) != 'employer':
        messages.error(request, "❌ Only employers can access employer dashboard.")
        return redirect('dashboard')

    posted_jobs_count = Job.objects.filter(employer=request.user).count()
    active_jobs = Job.objects.filter(employer=request.user, is_active=True).count()
    applicants_count = Application.objects.filter(job__employer=request.user).count()

    return render(request, 'employer_dashboard.html', {
        'posted_jobs_count': posted_jobs_count,
        'active_jobs': active_jobs,
        'applicants_count': applicants_count,
    })

@csrf_protect
@login_required
def employer_profile(request):
    if not request.user.is_superuser and _get_effective_role(request.user) != "employer":
        messages.error(request, "❌ Only employers can access employer profile.")
        return redirect("dashboard")

    return render(request, 'employer_profile.html', {
        'user': request.user
    })

@csrf_protect
@login_required
def company_profile(request):
    if not request.user.is_superuser and _get_effective_role(request.user) != "employer":
        messages.error(request, "❌ Only employers can access company profile.")
        return redirect("dashboard")

    company = None
    is_verified = False

    # Try to fetch the EmployerCompany associated with the logged-in user
    try:
        company = EmployerCompany.objects.get(user=request.user)
        is_verified = company.is_verified
    except EmployerCompany.DoesNotExist:
        # Handle case where user doesn't have an employer company yet
        pass

    # Adding relevant context for the template
    context = {
        "company": company,
        "company_verified": is_verified
    }

    return render(request, "company_profile.html", context)

@csrf_protect
@login_required
def admin_profile(request):
    """
    Simple admin profile page that shows details of the logged-in superuser.
    """
    if not (request.user.is_superuser or request.user.role == 'admin'):
        return redirect('dashboard')   # block access for normal users

    return render(request, 'admin_profile.html', {
        'admin': request.user,
    })

@csrf_protect
@login_required
def edit_profile(request):
    user = request.user

    # Ensure the Profile object exists
    profile, _ = Profile.objects.get_or_create(user=user)

    # Get the latest CV for this user
    latest_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()
    cv_filename = os.path.basename(latest_cv.cv.url) if latest_cv and latest_cv.cv else None

    if request.method == 'POST':
        form = EditProfileForm(request.POST, request.FILES, instance=user, user=user)
        if form.is_valid():
            user = form.save(commit=False)

            # Update profile picture if uploaded
            uploaded_pic = request.FILES.get('profile_pic')
            if uploaded_pic:
                profile.profile_pic = uploaded_pic
                profile.save()

            # Save user fields
            user.save()

            # Handle CV upload if a new file is provided
            uploaded_cv = request.FILES.get('upload_cv')
            if uploaded_cv:
                CVUpload.objects.create(applicant=user, cv=uploaded_cv)
                # Refresh latest CV and filename after upload
                latest_cv = CVUpload.objects.filter(applicant=user).order_by('-id').first()
                cv_filename = os.path.basename(latest_cv.cv.url) if latest_cv and latest_cv.cv else None

            # Redirect based on user role
            if user.is_superuser or user.role == 'admin':
                return redirect('admin_profile')
            elif user.role == 'employer':
                return redirect('employer_profile')
            else:
                return redirect('profile')
    else:
        form = EditProfileForm(instance=user, user=user)

    context = {
        'form': form,
        'profile_picture_url': profile.profile_pic.url if profile.profile_pic else None,
        'user_cv': latest_cv,
        'cv_filename': cv_filename,
    }

    return render(request, 'change_credentials.html', context)
    
# Job Posting
@csrf_protect
@login_required
def post_job(request):
    """
    Allow verified employers to post jobs.
    Automatically handles premium tagging, expiry, and notifications to JobAlert subscribers.
    """

    # 1️⃣ Only employers can post jobs
    if getattr(request.user, "role", None) != "employer":
        messages.error(request, "❌ Only employers can post jobs.")
        return redirect('available_jobs')

    # 2️⃣ Get company tied to USER
    try:
        company = request.user.employer_company
    except EmployerCompany.DoesNotExist:
        company = None

    # 3️⃣ Block unverified employer
    if not company or not company.is_verified:
        messages.warning(
            request,
            "⏳ Your company is not verified yet. Upload required documents to continue."
        )
        return redirect('upload_company_docs')

    # 4️⃣ Handle job posting
    if request.method == 'POST':
        form = JobForm(request.POST, request.FILES)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user  # Assign correct employer

            # --- Auto-set premium & expiry ---
            if job.salary and job.salary > 30000:
                job.is_premium = True
                if not job.premium_expiry:
                    job.premium_expiry = timezone.now() + timedelta(days=30)
            else:
                job.is_premium = False
                job.premium_expiry = None

            # --- Ensure expiry_date and is_active ---
            if not job.expiry_date:
                job.expiry_date = timezone.now() + timedelta(days=30)
            job.is_active = True  # Newly posted job is always active

            job.save()  # Save job

            # 5️⃣ Send email + notifications to matching JobAlert subscribers
            matches = JobAlert.objects.filter(
                job_title__icontains=job.title,
                location__iexact=job.location
            )

            job_link = request.build_absolute_uri(
                reverse('apply_job', kwargs={'job_id': job.id})
            )

            for alert in matches:
                # 📩 Email
                html_content = render_to_string('job_alert_email.html', {
                    'user': alert.user,
                    'job': job,
                    'job_url': job_link
                })
                brevo_send_email(
                    subject=f"New {job.title} Job Posted!",
                    recipient=alert.user.email,
                    html_content=build_branded_email(
                        title=f"New {job.title} Job Posted!",
                        body_html=html_content,
                        footer_text="Joblink Kenya • Job Alerts",
                    ),
                )

                # 🔔 App Notification
                Notification.objects.create(
                    user=alert.user,
                    title="New Job Alert",
                    message=f"A new job '{job.title}' has been posted in {job.location}.",
                )

            messages.success(request, "🎉 Job posted successfully & alerts sent!")
            return redirect('dashboard')

    else:
        form = JobForm()

    # 6️⃣ Render template normally
    return render(request, 'post_job.html', {'form': form, 'company': company})

@csrf_protect
@login_required
def edit_job(request, job_id):
    # Only allow the employer who posted the job to edit it
    job = get_object_or_404(Job, id=job_id, employer=request.user)

    if request.method == 'POST':
        form = JobForm(request.POST, request.FILES, instance=job)
        if form.is_valid():
            job = form.save(commit=False)
            job.employer = request.user  # Ensure correct employer assignment

            # --- Auto-set premium based on salary ---
            if job.salary and job.salary > 30000:
                job.is_premium = True
                # Set default premium expiry if not set
                if not job.premium_expiry:
                    job.premium_expiry = timezone.now() + timedelta(days=30)
            else:
                job.is_premium = False
                job.premium_expiry = None

            # --- Ensure expiry_date and is_active ---
            if not job.expiry_date:
                job.expiry_date = timezone.now() + timedelta(days=30)

            # Automatically update is_active based on expiry
            job.is_active = job.expiry_date > timezone.now()

            job.save()

            messages.success(request, "✅ Job updated successfully.")
            return redirect('dashboard')  # Or redirect to job_detail page
    else:
        form = JobForm(instance=job)

    return render(request, 'edit_job.html', {'form': form, 'job': job})

# Apply Job View with reCAPTCHA (NO VERIFICATION CHECK)
@csrf_protect
@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    # 1️⃣ Only applicants can apply
    if request.user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can apply to jobs.")
        return redirect('available_jobs')

    # 2️⃣ Prevent applicant from applying to their own job (in case they are employer)
    if job.employer == request.user:
        messages.error(request, "❌ You cannot apply to your own job posting.")
        return redirect('available_jobs')

    # 3️⃣ Handle POST requests
    if request.method == "POST":
        # --------------------------
        # Verify Google reCAPTCHA
        # --------------------------
        recaptcha_response = request.POST.get('g-recaptcha-response')
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, 'apply_job.html', {'job': job})

        recaptcha_data = {
            'secret': settings.RECAPTCHA_SECRET,
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=recaptcha_data)
        result = r.json()
        if not result.get('success'):
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return render(request, 'apply_job.html', {'job': job})
        # --------------------------

        # ---------- FREE JOB FLOW ----------
        if not job.is_premium:
            application, created = Application.objects.get_or_create(
                applicant=request.user,
                job=job
            )

            if created:
                # Notify employer
                Notification.objects.create(
                    user=job.employer,
                    title="New Job Application",
                    message=f"{request.user.username} has applied for your job '{job.title}'. (job_id={job.id})"
                )
                applied_status = 'yes'
                messages.success(request, f"✅ You have successfully applied to {job.title}!")
            else:
                applied_status = 'already'
                messages.info(request, f"ℹ️ You already applied for {job.title}.")

            return redirect('apply_job_success', job_id=job.id, applied=applied_status)

        # ---------- PREMIUM JOB FLOW ----------
        # NO VERIFICATION CHECK — can apply regardless
        amount = 200 * 100  # KES 200 in cents
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'kes',
                        'product_data': {'name': f"Application Fee - {job.title}"},
                        'unit_amount': amount,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri(f'/apply-success/{job.id}/yes/'),
                cancel_url=request.build_absolute_uri(f'/apply-cancel/{job.id}/'),
                metadata={
                    'job_id': job.id,
                    'user_id': request.user.id
                }
            )
            return redirect(checkout_session.url)

        except stripe.error.StripeError as e:
            return render(request, 'apply_job.html', {'job': job, 'error': getattr(e, 'user_message', str(e))})
        except Exception as e:
            return render(request, 'apply_job.html', {'job': job, 'error': str(e)})

    # GET request → Show application page
    return render(request, 'apply_job.html', {'job': job})

@csrf_protect
@login_required
def apply_job_success(request, job_id, applied):
    """
    Display the job application status page.
    'applied' is 'yes' if the user just applied, 'already' if they applied before.
    """
    job = get_object_or_404(Job, pk=job_id)

    # Determine success boolean based on applied flag
    success = applied == "yes"

    # Render the status page without adding messages again
    return render(request, "apply_job_success.html", {
        "job": job,
        "success": success
    })
    
#CV Upload
@csrf_protect
@login_required
def upload_cv(request):
    form = CVUploadForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        cv = form.save(commit=False)
        cv.applicant = request.user
        cv.save()
        return redirect('profile')
    return render(request, 'upload_CV.html', {'form': form})

@csrf_protect
@login_required
def download_cv(request, cv_id):
    cv = get_object_or_404(CVUpload, id=cv_id)

    if not cv.cv:
        return HttpResponse("No CV uploaded.", status=404)

    # Download file from Cloudinary
    response = requests.get(cv.cv.url, stream=True)
    if response.status_code != 200:
        return HttpResponse("Error downloading CV.", status=500)

    # Save to temporary file
    temp_file = NamedTemporaryFile(delete=True)
    for chunk in response.iter_content(1024):
        temp_file.write(chunk)
    temp_file.flush()

    # Use the correct applicant field for filename
    applicant_name = getattr(cv, 'applicant', None)
    if applicant_name:
        filename = f"{cv.applicant.username}_CV.pdf"
    else:
        filename = "CV.pdf"

    # Serve file as attachment
    return FileResponse(
        open(temp_file.name, 'rb'),
        as_attachment=True,
        filename=filename
    )
    
@csrf_protect
@login_required
def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    # Default: no application
    application = None  

    # If user is an applicant, check if they already applied and not soft-deleted
    if getattr(request.user, "profile", None) and request.user.profile.role == "applicant":
        application = Application.objects.filter(
            job=job,
            applicant=request.user,
            is_deleted=False  # ignore soft-deleted applications
        ).first()

    context = {
        "job": job,
        "application": application,
    }
    return render(request, "job_detail.html", context)

#Learning Resources
@csrf_protect
def resources(request):
    items = SkillResource.objects.all()
    return render(request, 'resources.html', {'items': items})
    
@csrf_protect
@login_required
def job_alerts_view(request):
    # Ensure only applicants can create job alerts
    if not getattr(request.user, "profile", None) or request.user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can create job alerts.")
        return redirect('dashboard')

    alerts = JobAlert.objects.filter(user=request.user)

    if request.method == 'POST':
        # --------------------------
        # 0️⃣ Verify Google reCAPTCHA
        # --------------------------
        recaptcha_response = request.POST.get('g-recaptcha-response')
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, 'job_alerts.html', {'alerts': alerts})

        recaptcha_data = {
            'secret': settings.RECAPTCHA_SECRET,
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=recaptcha_data)
        result = r.json()

        if not result.get('success'):
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return render(request, 'job_alerts.html', {'alerts': alerts})
        # --------------------------

        # Create new job alert
        job_title = request.POST.get('job_title', '').strip()
        location = request.POST.get('location', '').strip()

        if job_title and location:
            JobAlert.objects.create(
                user=request.user,
                job_title=job_title,
                location=location
            )
            messages.success(request, "✅ Job alert created successfully!")
        else:
            messages.error(request, "Please provide both job title and location.")

        return redirect('job_alerts')

    return render(request, 'job_alerts.html', {'alerts': alerts})

# Delete Job Alert with reCAPTCHA
@csrf_protect
@login_required
def delete_alert(request, alert_id):
    try:
        alert = JobAlert.objects.get(id=alert_id, user=request.user)
    except JobAlert.DoesNotExist:
        messages.warning(request, "That job alert does not exist or was already deleted.")
        return redirect('delete_alert_success')

    if request.method == 'POST':
        # --------------------------
        # 0️⃣ Verify Google reCAPTCHA
        # --------------------------
        recaptcha_response = request.POST.get('g-recaptcha-response')
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, 'delete_alert.html', {'alert': alert})

        recaptcha_data = {
            'secret': settings.RECAPTCHA_SECRET,  # Ensure this is set in settings.py
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=recaptcha_data)
        result = r.json()

        if not result.get('success'):
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return render(request, 'delete_alert.html', {'alert': alert})
        # --------------------------

        # Delete the alert
        alert.delete()
        messages.success(request, "✅ Job alert deleted successfully.")
        return redirect('delete_alert_success')

    return render(request, 'delete_alert.html', {'alert': alert})
    
@csrf_protect
def delete_alert_success(request):
    return render(request, 'delete_alert_success.html')

@csrf_protect
@login_required
def confirm_delete(request, job_id):
    job = get_object_or_404(Job, id=job_id, employer=request.user)  # Ensure user owns the job

    if request.method == "POST":
        job.delete()
        messages.success(request, "✅ Job deleted successfully!")
        return redirect('view_posted_jobs')  # Redirect to list after deletion

    return render(request, 'confirm_delete.html', {'job': job})
    
#Admin Dashboard
@csrf_protect
@login_required
@user_passes_test(lambda u: u.is_superuser or u.role == 'admin')
def admin_dashboard(request):
    context = {
        'total_users': CustomUser.objects.count(),
        'total_jobs': Job.objects.count(),
        'total_alerts': JobAlert.objects.count(),
        'total_reports': 0,  # or change to real Report count
        'recent_users': CustomUser.objects.order_by('-date_joined')[:5],
    }
    return render(request, 'admin_dashboard.html', context)
    
@csrf_protect
@login_required 
def admin_required(user):
    return user.role == 'admin'
    
@csrf_protect
@login_required 
def admin_only_view(request):
    if request.user.role != 'admin':
        return redirect('home')
    return render(request, 'admin_only.html')
    
@csrf_protect    
@login_required
def resume_success(request):
    """Simple success page after resume is saved."""
    return render(request, 'resume_success.html')

# Constants
CANVA_CLIENT_ID = 'OC-AZw940cg5ae3'
CANVA_REDIRECT_URI = 'https://stepper.dpdns.org/oauth/canva/callback'  # Dedicated redirect handler
CANVA_AUTH_URL = 'https://www.canva.com/api/oauth/authorize'
CANVA_EDITOR_URL = 'https://www.canva.com/design/new'

# Helper: Generate PKCE code challenge
def generate_code_challenge():
    code_verifier = secrets.token_urlsafe(64)  # 43–128 chars
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

@csrf_protect
@login_required
def alien_resume_builder(request):
    """Open Canva editor when authorized, otherwise start Canva OAuth flow."""

    # Reuse existing token instead of forcing OAuth on every click.
    if request.session.get('canva_access_token'):
        return redirect(CANVA_EDITOR_URL)

    # 1. Generate PKCE code challenge and store code_verifier in session
    code_verifier, code_challenge = generate_code_challenge()
    request.session['canva_code_verifier'] = code_verifier

    # 2. Generate CSRF protection state only if it doesn't exist
    if not request.session.get('canva_oauth_state'):
        state = secrets.token_urlsafe(16)
        request.session['canva_oauth_state'] = state
    else:
        state = request.session['canva_oauth_state']

    # 3. Define required scopes
    scopes = [
        'asset:read',
        'design:content:write',
        'collaboration:event',
        'asset:write',
        'design:permission:read',
        'design:permission:write',
        'folder:write',
        'comment:read',
        'profile:read',
        'design:content:read',
        'app:write',
        'app:read',
        'folder:permission:write',
        'folder:permission:read',
        'brandtemplate:content:read',
        'design:meta:read',
        'folder:read',
        'comment:write',
        'brandtemplate:meta:read',
    ]

    # 4. Build query params
    query_params = {
        'code_challenge_method': 's256',
        'response_type': 'code',
        'client_id': CANVA_CLIENT_ID,
        'redirect_uri': CANVA_REDIRECT_URI,
        'scope': ' '.join(scopes),
        'code_challenge': code_challenge,
        'state': state,
    }

    canva_authorize_url = f"{CANVA_AUTH_URL}?{urllib.parse.urlencode(query_params)}"

    # 5. Redirect user to Canva OAuth
    return redirect(canva_authorize_url)

# Constants
CANVA_CLIENT_ID = 'OC-AZw940cg5ae3'
CANVA_CLIENT_SECRET = os.getenv('CANVA_CLIENT_SECRET')  # Keep secret in env
CANVA_TOKEN_URL = 'https://api.canva.com/rest/v1/oauth/token'
REDIRECT_URI = 'https://stepper.dpdns.org/oauth/canva/callback'

@login_required
@csrf_exempt
def canva_oauth_callback(request):
    """
    Handles redirect from Canva after user authorizes app.
    Exchanges code for access token and stores it in session.
    """
    # 1. Check for error from Canva
    error = request.GET.get('error')
    if error:
        return HttpResponse(f"Authorization failed: {error}", status=400)

    # 2. Get code and state
    code = request.GET.get('code')
    returned_state = request.GET.get('state')
    stored_state = request.session.get('canva_oauth_state')
    code_verifier = request.session.get('canva_code_verifier')

    # 3. Basic validations
    if not code:
        return HttpResponse("No authorization code received.", status=400)
    if not stored_state:
        return HttpResponse("Session expired or state missing.", status=400)
    if returned_state != stored_state:
        return HttpResponse("Invalid state parameter.", status=400)
    if not code_verifier:
        return HttpResponse("Missing code verifier in session.", status=400)

    # 4. Exchange authorization code for access token
    payload = {
        'client_id': CANVA_CLIENT_ID,
        'client_secret': CANVA_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    
    try:
        response = requests.post(CANVA_TOKEN_URL, data=payload, headers=headers, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        error_details = ''
        if getattr(e, 'response', None) is not None:
            error_details = f" | Response: {e.response.text}"
        return HttpResponse(f"Token exchange failed: {str(e)}{error_details}", status=500)

    token_data = response.json()

    # 5. Store tokens in session or database (recommended)
    request.session['canva_access_token'] = token_data.get('access_token')
    request.session['canva_refresh_token'] = token_data.get('refresh_token')

    # 6. Clean up temporary session variables
    request.session.pop('canva_code_verifier', None)
    request.session.pop('canva_oauth_state', None)

    # 7. Redirect user directly to Canva editor after authorization.
    return redirect(CANVA_EDITOR_URL)
    
# Optional: store your webhook secret from Canva
CANVA_WEBHOOK_SECRET = os.getenv('CANVA_WEBHOOK_SECRET', 'super-secret-key')

@csrf_exempt
def canva_webhook(request):
    """
    Endpoint to receive Canva webhook events.
    """
    if request.method != 'POST':
        return HttpResponse("Only POST requests are allowed.", status=405)

    # Get raw body for signature verification
    payload = request.body

    # Optional: verify signature if Canva provides X-Canva-Signature
    signature = request.headers.get('X-Canva-Signature')
    if signature:
        computed_sig = hmac.new(
            key=CANVA_WEBHOOK_SECRET.encode('utf-8'),
            msg=payload,
            digestmod=hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, computed_sig):
            return HttpResponse("Invalid signature", status=403)

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return HttpResponse("Invalid JSON", status=400)

    # Example: log or process event
    event_type = data.get('event')
    event_data = data.get('data', {})

    print(f"Received Canva event: {event_type}")
    print(f"Event data: {event_data}")

    # TODO: Add your processing logic here, e.g., update DB, trigger actions

    # Respond with 200 OK to acknowledge receipt
    return JsonResponse({'status': 'success'})
    
@csrf_protect
@login_required
def view_resume(request):
    """View the resume content or uploaded file."""
    resume = Resume.objects.filter(user=request.user).first()
    return render(request, 'view_resume.html', {'resume': resume})

@csrf_protect
@login_required
def download_resume_pdf(request):
    """Generate and download resume as PDF from saved content."""
    resume = get_object_or_404(Resume, user=request.user)
    
    # Use editor HTML content if available, else fallback to uploaded file
    html_string = render_to_string('resume_template.html', {'resume': resume})

    pdf_file = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf()

    response = HttpResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="resume.pdf"'
    return response
    
@csrf_protect
@login_required
def job_suggestions(request):
    user = request.user
    
    # Ensure skills is always a string before splitting
    skills_str = getattr(user, "skills", "") or ""
    skills = [s.strip().lower() for s in skills_str.split(",") if s.strip()]

    if skills:
        query = Q()
        for skill in skills:
            # Split multi-word skills into words
            for word in skill.split():
                # Partial + case-insensitive match
                query |= Q(title__icontains=word) | Q(description__icontains=word)

        suggested_jobs = Job.objects.filter(query).distinct()

        if not suggested_jobs.exists():
            messages.warning(
                request,
                "No jobs matched your skills. Try updating your profile for better matches."
            )
    else:
        if not request.session.get("skills_message_shown", False):
            messages.info(request, "Add skills in your profile to get better job matches.")
            request.session["skills_message_shown"] = True

        suggested_jobs = Job.objects.none()

    return render(request, "suggestions.html", {
        "suggested_jobs": suggested_jobs
    })

@csrf_protect
@login_required
def change_username_password(request):
    """
    Change username and password view with Google reCAPTCHA verification
    """
    if request.method == 'POST':
        form = ChangeUsernamePasswordForm(request.POST, user=request.user, instance=request.user)
        recaptcha_response = request.POST.get('g-recaptcha-response')

        # 0️⃣ Verify Google reCAPTCHA
        if not recaptcha_response:
            messages.error(request, "Please complete the reCAPTCHA.")
            return render(request, 'change_username_password.html', {'form': form})

        recaptcha_data = {
            'secret': RECAPTCHA_SECRET,
            'response': recaptcha_response
        }
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=recaptcha_data)
        result = r.json()

        if not result.get('success'):
            messages.error(request, "reCAPTCHA verification failed. Please try again.")
            return render(request, 'change_username_password.html', {'form': form})

        # 1️⃣ Validate form
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['new_password1'])
            user.save()
            update_session_auth_hash(request, user)  # keeps user logged in
            messages.success(request, "Account updated successfully!")
            return redirect('profile')  # ensure this URL exists
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ChangeUsernamePasswordForm(user=request.user, instance=request.user)

    return render(request, 'change_username_password.html', {'form': form})

def chat_view(request, application_id=None, job_id=None):
    """
    Unified chat view for both applicants and employers.
    - Applicants access via application_id
    - Employers access via job_id (with optional ?app_id= query param)
    - General landing if neither is provided
    Soft-deleted applications are hidden from the respective users.
    """
    if not request.user.is_authenticated:
        return redirect_to_login(request.get_full_path(), login_url=settings.LOGIN_URL)

    # Avoid django_ratelimit decorator async/sync wrapper issues on this endpoint.
    if is_ratelimited(
        request=request,
        group="chat_view",
        key="ip",
        rate="10/m",
        method=["GET", "POST"],
        increment=True,
    ):
        return HttpResponseForbidden("Too many requests")

    user = request.user
    context = {
        "application": None,
        "job": None,
        "applications": [],
        "selected_app": None,
        "messages": [],
        "jobs": [],
    }

    messages_list = []
    selected_app = None

    # -----------------------------
    # Case 1: Applicant chat
    # -----------------------------
    if application_id:
        app = get_object_or_404(
            Application.objects.select_related("job", "applicant", "job__employer"),
            id=application_id,
            is_deleted=False  # applicant should not see deleted apps
        )

        # Security check
        if user.id not in (app.applicant_id, app.job.employer_id):
            messages.error(request, "❌ You are not authorized to view this chat.")
            return redirect("job_detail", job_id=app.job_id)

        # Handle new message
        if request.method == "POST":
            text = request.POST.get("message")
            if text:
                ChatMessage.objects.create(application=app, sender=user, message=text)

                recipient = app.job.employer if user == app.applicant else app.applicant
                Notification.objects.create(
                    user=recipient,
                    title="New Chat Message",
                    message=f"{user.username} sent you a new message about '{app.job.title}'."
                )

        messages_list = app.messages.all().order_by("timestamp")
        selected_app = app

        # Mark employer messages as read when applicant views
        if user == app.applicant:
            ChatMessage.objects.filter(
                application=app,
                sender_id=app.job.employer_id,
                is_read=False
            ).update(is_read=True)

        context.update({
            "application": app,
            "messages": messages_list,
            "selected_app": selected_app,
        })

    # -----------------------------
    # Case 2: Employer chat (per job)
    # -----------------------------
    elif job_id:
        job = get_object_or_404(Job, id=job_id, employer=user)

        # Exclude applications hidden by applicant
        applications = job.applications.filter(is_deleted_for_employer=False).select_related("applicant").annotate(
            unread_count=Count(
                "messages",
                filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id")),
            )
        )

        # Pick selected application
        selected_app_id = request.GET.get("app_id")
        if selected_app_id:
            try:
                selected_app_id = int(selected_app_id)
                selected_app = applications.filter(id=selected_app_id).first()
            except ValueError:
                selected_app = None

        if not selected_app:
            selected_app = applications.first() if applications else None

        # Handle new message
        if request.method == "POST" and selected_app:
            text = request.POST.get("message")
            if text:
                ChatMessage.objects.create(application=selected_app, sender=user, message=text)

                Notification.objects.create(
                    user=selected_app.applicant,
                    title="New Chat Message",
                    message=f"{user.username} (employer) sent you a new message about '{selected_app.job.title}'."
                )

        messages_list = selected_app.messages.all().order_by("timestamp") if selected_app else []

        # Mark applicant messages as read when employer views
        if selected_app:
            ChatMessage.objects.filter(
                application=selected_app,
                sender_id=selected_app.applicant_id,
                is_read=False
            ).update(is_read=True)

        context.update({
            "job": job,
            "applications": applications,
            "selected_app": selected_app,
            "messages": messages_list,
        })

    # -----------------------------
    # Case 3: General landing
    # -----------------------------
    else:
        if _get_effective_role(user) == "employer":
            jobs = Job.objects.filter(employer=user).prefetch_related(
                "applications__applicant"
            )

            job = None
            applications = []
            selected_app = None
            messages_list = []

            # Pick job from query (?job_id=...)
            job_id_param = request.GET.get("job_id")
            if job_id_param:
                try:
                    job = jobs.filter(id=int(job_id_param)).first()
                except ValueError:
                    job = None

            # Default: first job if none chosen
            if not job and jobs.exists():
                job = jobs.first()

            if job:
                applications = job.applications.filter(is_deleted_for_employer=False).select_related("applicant").annotate(
                    unread_count=Count(
                        "messages",
                        filter=Q(messages__is_read=False) & Q(messages__sender_id=F("applicant_id")),
                    )
                )

                # Pick applicant (?app_id=...)
                selected_app_id = request.GET.get("app_id")
                if selected_app_id:
                    try:
                        selected_app = applications.filter(id=int(selected_app_id)).first()
                    except ValueError:
                        selected_app = None

                if not selected_app and applications.exists():
                    selected_app = applications.first()

                if selected_app:
                    messages_list = selected_app.messages.select_related(
                        "sender",
                        "reply_to",
                        "reply_to__sender",
                    ).order_by("timestamp")

            context.update({
                "jobs": jobs,
                "job": job,
                "applications": applications,
                "selected_app": selected_app,
                "messages": messages_list,
            })

        else:
            # Applicant view: show all their applications except deleted
            applications = Application.objects.filter(
                applicant=user,
                is_deleted=False
            ).select_related("job__employer")
            selected_app = None
            messages_list = []

            # Pick one if requested (?app_id=...)
            selected_app_id = request.GET.get("app_id")
            if selected_app_id:
                try:
                    selected_app = applications.filter(id=int(selected_app_id)).first()
                except ValueError:
                    selected_app = None

            if not selected_app and applications.exists():
                selected_app = applications.first()

            if selected_app:
                messages_list = selected_app.messages.select_related(
                    "sender",
                    "reply_to",
                    "reply_to__sender",
                ).order_by("timestamp")

            context.update({
                "applications": applications,
                "selected_app": selected_app,
                "messages": messages_list,
            })

    # -----------------------------
    # AJAX response
    # -----------------------------
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JsonResponse({
            "messages": [
                {
                    "id": msg.id,
                    "sender_id": msg.sender_id,
                    "text": msg.message,
                    "created": msg.timestamp.strftime("%Y-%m-%d %H:%M"),
                }
                for msg in messages_list
            ],
            "selected_app_id": selected_app.id if selected_app else None
        })

    # Render always with chat.html
    return render(request, "chat.html", context)
                
# ======================================================
# VIEW APPLICANT'S JOB APPLICATIONS
# ======================================================
@csrf_protect
@login_required
def view_applications(request):
    """
    Show jobs the logged-in applicant has applied to
    with current status, and auto-delete expired soft-deleted applications.
    """
    user = request.user

    # ✅ Use profile.role if role is stored in the Profile model
    if user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can access this page.")
        return redirect("dashboard")

    # -----------------------------
    # Auto-delete expired soft-deleted applications
    # -----------------------------
    expired_deleted_apps = []
    soft_deleted_apps = Application.objects.filter(applicant=user, is_deleted=True)
    for app in soft_deleted_apps:
        if app.is_expired():
            # Remove related chat messages
            ChatMessage.objects.filter(application=app).delete()

            # Remove related notifications to employer
            Notification.objects.filter(
                user=app.job.employer,
                message__icontains=f"{user.username}"
            ).delete()

            # Delete the application
            app.delete()
            expired_deleted_apps.append(app)

    # -----------------------------
    # Fetch active applications
    # -----------------------------
    active_applications = (
        Application.objects.filter(applicant=user, is_deleted=False)
        .select_related("job", "job__employer")
        .order_by("-applied_on")
    )

    context = {
        "applications": active_applications,
        "applications_count": active_applications.count(),
        "deleted_apps": expired_deleted_apps,
    }

    return render(request, "view_applications.html", context)

# ======================================================
# DELETE APPLICATION (Soft delete)
# ======================================================
@csrf_protect
@login_required
def delete_application(request, app_id):
    """
    Soft delete an application for the applicant and hide it from the employer.
    Works with SweetAlert AJAX.
    """
    user = request.user

    # Ensure only applicants can delete their applications
    if user.profile.role != "applicant":
        return JsonResponse({
            "success": False,
            "message": "❌ Only applicants can delete applications."
        }, status=403)

    if request.method == "POST":
        app = get_object_or_404(Application, id=app_id, applicant=user)

        # -------------------------------
        # Soft delete for applicant
        # -------------------------------
        app.is_deleted = True
        app.deleted_on = timezone.now()
        
        # -------------------------------
        # Hide from employer
        # -------------------------------
        app.is_deleted_for_employer = True
        app.save()

        # -------------------------------
        # Remove related notifications and chat messages
        # -------------------------------
        Notification.objects.filter(
            user=app.job.employer,
            message__icontains=f"{user.username}"
        ).delete()

        ChatMessage.objects.filter(application=app).delete()

        return JsonResponse({
            "success": True,
            "message": "✅ Application moved to Recycle Bin and hidden from employer."
        })

    return JsonResponse({
        "success": False,
        "message": "Invalid request."
    }, status=400)

# ======================================================
# UNDO DELETE APPLICATION
# ======================================================
@csrf_protect
@login_required
def undo_delete_application(request, app_id):
    """
    Restore a soft-deleted application for the applicant
    and make it visible again to the employer.
    """
    user = request.user

    # Ensure only applicants can restore applications
    if user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can restore applications.")
        return redirect("dashboard")

    app = get_object_or_404(Application, id=app_id, applicant=user)

    # Restore for applicant
    app.is_deleted = False
    app.deleted_on = None

    # Restore visibility for employer
    app.is_deleted_for_employer = False
    app.save()

    messages.success(request, "✅ Application restored successfully and is now visible to the employer!")
    return redirect("recycle_bin")

# ======================================================
# PERMANENT DELETE APPLICATION (Destroy)
# ======================================================
@csrf_protect
@login_required
def destroy_application(request, app_id):
    """
    Permanently delete a soft-deleted application along with its related
    chat messages and notifications. Only accessible to applicants.
    """
    user = request.user

    # Ensure only applicants can permanently delete applications
    if user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can permanently delete applications.")
        return redirect("dashboard")

    app = get_object_or_404(Application, id=app_id, applicant=user)

    # Delete related chat messages and employer notifications
    ChatMessage.objects.filter(application=app).delete()
    Notification.objects.filter(user=app.job.employer).delete()

    # Permanently delete the application
    app.delete()

    messages.success(request, "✅ Application permanently deleted.")
    return redirect("recycle_bin")

# ======================================================
# RECYCLE BIN VIEW
# ======================================================
@csrf_protect
@login_required
def recycle_bin(request):
    """
    Show all soft-deleted applications for the logged-in applicant.
    Auto-delete expired applications (7+ days) permanently.
    """
    user = request.user

    # Ensure only applicants can access recycle bin
    if user.profile.role != "applicant":
        messages.error(request, "❌ Only applicants can access the Recycle Bin.")
        return redirect("dashboard")

    # Fetch soft-deleted applications
    deleted_apps = Application.objects.filter(applicant=user, is_deleted=True)

    # Auto-delete expired applications
    for app in deleted_apps:
        if app.is_expired():  # Ensure this method exists in Application model
            # Remove related chat messages
            ChatMessage.objects.filter(application=app).delete()
            # Remove related notifications
            Notification.objects.filter(user=app.job.employer).delete()
            # Permanently delete application
            app.delete()

    # Re-fetch remaining deleted apps after auto-delete
    deleted_apps = Application.objects.filter(applicant=user, is_deleted=True)

    return render(request, "recycle_bin.html", {
        "deleted_apps": deleted_apps
    })
