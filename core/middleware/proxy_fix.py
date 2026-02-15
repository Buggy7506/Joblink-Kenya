import json


_HTTPS_HINT_HEADERS = (
    "HTTP_X_FORWARDED_PROTO",
    "HTTP_X_FORWARDED_PROTOCOL",
    "HTTP_X_FORWARDED_SCHEME",
    "HTTP_X_URL_SCHEME",
    "HTTP_X_SCHEME",
    "HTTP_CLOUDFRONT_FORWARDED_PROTO",
)


def _extract_forwarded_values(request):
    values = []
    for header in _HTTPS_HINT_HEADERS:
        raw = request.META.get(header, "")
        if not raw:
            continue
        values.extend(value.strip().lower() for value in raw.split(",") if value.strip())
    return values


def _coerce_https_from_proxy_headers(request):
    """Best-effort HTTPS detection across common reverse proxy headers."""
    forwarded_values = _extract_forwarded_values(request)
    if "https" in forwarded_values:
        return True

    if request.META.get("HTTP_X_FORWARDED_SSL", "").strip().lower() == "on":
        return True

    if request.META.get("HTTP_FRONT_END_HTTPS", "").strip().lower() == "on":
        return True

    forwarded = request.META.get("HTTP_FORWARDED", "")
    if "proto=https" in forwarded.lower():
        return True

    cf_visitor = request.META.get("HTTP_CF_VISITOR")
    if cf_visitor:
        try:
            visitor_data = json.loads(cf_visitor)
        except (TypeError, ValueError):
            visitor_data = {}
        if visitor_data.get("scheme") == "https":
            return True

    return False


class ProxyHeaderNormalizeMiddleware:
    """Normalize proxy headers so Django sees the original request scheme/host."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        forwarded_proto = request.META.get("HTTP_X_FORWARDED_PROTO")
        if not forwarded_proto:
            for header in _HTTPS_HINT_HEADERS:
                if header == "HTTP_X_FORWARDED_PROTO":
                    continue
                candidate = request.META.get(header)
                if candidate:
                    forwarded_proto = candidate
                    request.META["HTTP_X_FORWARDED_PROTO"] = candidate
                    break

        if forwarded_proto:
            normalized_values = [value.strip() for value in forwarded_proto.split(",") if value.strip()]
            if normalized_values:
                request.META["HTTP_X_FORWARDED_PROTO"] = (
                    "https" if any(value.lower() == "https" for value in normalized_values) else normalized_values[0]
                )

        forwarded_host = request.META.get("HTTP_X_FORWARDED_HOST")
        if forwarded_host:
            request.META["HTTP_X_FORWARDED_HOST"] = forwarded_host.split(",")[0].strip()

        if _coerce_https_from_proxy_headers(request):
            request.META["HTTP_X_FORWARDED_PROTO"] = "https"

        return self.get_response(request)
