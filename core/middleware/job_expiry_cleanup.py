from django.utils import timezone

from core.models import Job


class ExpiredJobCleanupMiddleware:
    """
    Hard-delete expired jobs so they disappear from all surfaces immediately.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        Job.objects.filter(expiry_date__isnull=False, expiry_date__lte=timezone.now()).delete()
        return self.get_response(request)
