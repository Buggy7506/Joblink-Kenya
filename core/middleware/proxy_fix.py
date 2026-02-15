import json


class ProxyHeaderNormalizeMiddleware:
    """Normalize proxy headers so Django sees the original request scheme/host."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        forwarded_proto = request.META.get("HTTP_X_FORWARDED_PROTO")
        if forwarded_proto:
            request.META["HTTP_X_FORWARDED_PROTO"] = forwarded_proto.split(",")[0].strip()

        forwarded_host = request.META.get("HTTP_X_FORWARDED_HOST")
        if forwarded_host:
            request.META["HTTP_X_FORWARDED_HOST"] = forwarded_host.split(",")[0].strip()

        # Cloudflare sends the original client scheme in CF-Visitor.
        # If present, prefer it to avoid HTTPS redirect loops behind flexible proxies.
        cf_visitor = request.META.get("HTTP_CF_VISITOR")
        if cf_visitor:
            try:
                visitor_data = json.loads(cf_visitor)
            except (TypeError, ValueError):
                visitor_data = {}
            if visitor_data.get("scheme") == "https":
                request.META["HTTP_X_FORWARDED_PROTO"] = "https"

        return self.get_response(request)
