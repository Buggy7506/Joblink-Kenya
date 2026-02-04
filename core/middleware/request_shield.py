from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden, HttpResponseNotFound


class RequestShieldMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        config = getattr(settings, "REQUEST_SHIELD", {})
        self.enabled = config.get("ENABLED", True)
        self.rate_limit_window = config.get("RATE_LIMIT_WINDOW_SECONDS", 60)
        self.rate_limit_max = config.get("RATE_LIMIT_MAX_REQUESTS", 240)
        self.block_user_agents = config.get("BLOCK_USER_AGENTS", True)
        self.block_paths = config.get("BLOCK_PATHS", True)
        self.safe_prefixes = ("/static/", "/media/")
        self.blocked_path_fragments = (
            "/.env",
            "/.git",
            "/.hg",
            "/.svn",
            "/wp-admin",
            "/wp-login",
            "/phpmyadmin",
            "/mysql",
            "/cgi-bin",
            "/vendor/phpunit",
            "/actuator",
            "/server-status",
            "/etc/passwd",
            ".sql",
            ".bak",
            ".old",
            ".zip",
            ".tar",
            ".gz",
        )
        self.blocked_user_agent_tokens = (
            "sqlmap",
            "nikto",
            "dirb",
            "gobuster",
            "ffuf",
            "acunetix",
            "wpscan",
            "masscan",
            "nmap",
        )

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        path = (request.path_info or "").lower()
        for prefix in self.safe_prefixes:
            if path.startswith(prefix):
                return self.get_response(request)

        if self.block_paths and self._matches_blocked_path(path):
            return HttpResponseNotFound()

        user_agent = (request.META.get("HTTP_USER_AGENT") or "").lower()
        if self.block_user_agents and self._matches_blocked_user_agent(user_agent):
            return HttpResponseForbidden("Forbidden")

        client_ip = self._get_client_ip(request)
        if client_ip:
            cache_key = f"request-shield:{client_ip}"
            current = cache.get(cache_key, 0)
            if current >= self.rate_limit_max:
                return HttpResponseForbidden("Too many requests")
            cache.set(cache_key, current + 1, timeout=self.rate_limit_window)

        return self.get_response(request)

    def _matches_blocked_path(self, path):
        return any(token in path for token in self.blocked_path_fragments)

    def _matches_blocked_user_agent(self, user_agent):
        return any(token in user_agent for token in self.blocked_user_agent_tokens)

    def _get_client_ip(self, request):
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")
