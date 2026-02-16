from asgiref.sync import iscoroutinefunction
from inspect import isawaitable
from django.utils import timezone

from core.models import Job


class ExpiredJobCleanupMiddleware:
    """
    Hard-delete expired jobs so they disappear from all surfaces immediately.
    """

    async_capable = True
    sync_capable = True

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if iscoroutinefunction(self.get_response):
            return self.__acall__(request)

        self._cleanup_expired_jobs()
        return self.get_response(request)

    async def __acall__(self, request):
        self._cleanup_expired_jobs()
                response = self.get_response(request)
        if isawaitable(response):
            return await response
        return response

    def _cleanup_expired_jobs(self):
        Job.objects.filter(expiry_date__isnull=False, expiry_date__lte=timezone.now()).delete()
