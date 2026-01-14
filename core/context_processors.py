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
