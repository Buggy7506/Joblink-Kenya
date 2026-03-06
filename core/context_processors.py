import hashlib
import hmac

from django.conf import settings

from .models import EmployerCompany

def employer_badge(request):
    """
    Adds `company_verified` to the template context.
    True  -> employer company is verified
    False -> employer is unverified or has not created a company
    """
    verified = False

    if request.user.is_authenticated:
        try:
            company = EmployerCompany.objects.get(user=request.user)
            verified = company.is_verified
        except EmployerCompany.DoesNotExist:
            verified = False

    return {"company_verified": verified}


def jotform_agent_user(request):
    """
    Adds authenticated user identity payload for Jotform Agent SDK.
    """
    secret = getattr(settings, "JF_AGENT_SECRET", "")

    if not request.user.is_authenticated or not secret:
        return {"jf_identified_user": None}

    user_id = str(request.user.id)
    user_hash = hmac.new(secret.encode(), user_id.encode(), hashlib.sha256).hexdigest()

    metadata = {
        "name": request.user.get_full_name() or request.user.username or "",
        "email": request.user.email or "",
    }

    employer_company = getattr(request.user, "employer_company", None)
    if employer_company and employer_company.company_name:
        metadata["company"] = employer_company.company_name

    return {
        "jf_identified_user": {
            "metadata": metadata,
            "userID": user_id,
            "userHash": user_hash,
        }
    }
