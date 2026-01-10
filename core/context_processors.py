def employer_badge(request):
    if request.user.is_authenticated:
        try:
            company = Company.objects.get(owner=request.user)
            return {"company_verified": company.is_verified}
        except Company.DoesNotExist:
            pass
    return {}
