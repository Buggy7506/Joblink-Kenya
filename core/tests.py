from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, SimpleTestCase, TestCase
from django.urls import reverse

from core.views import _get_effective_role, _normalize_next_url, view_posted_jobs


class NextRedirectTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_normalize_next_url_accepts_relative_path(self):
        request = self.factory.get("/Sign-In-OR-Sign-Up/")
        request.META["HTTP_HOST"] = "testserver"

        self.assertEqual(_normalize_next_url(request, "/profile/"), "/profile/")

    def test_normalize_next_url_rejects_external_url(self):
        request = self.factory.get("/Sign-In-OR-Sign-Up/")
        request.META["HTTP_HOST"] = "testserver"

        self.assertIsNone(_normalize_next_url(request, "https://malicious.example/profile/"))


class OAuthNextPersistenceTests(TestCase):
    def test_google_login_persists_safe_next_in_session(self):
        client = Client()

        response = client.get("/auth/google/?next=/profile/")

        self.assertEqual(response.status_code, 302)
        self.assertIn("accounts.google.com", response["Location"])
        self.assertEqual(client.session.get("auth_next"), "/profile/")

    def test_google_login_ignores_external_next(self):
        client = Client()

        response = client.get("/auth/google/?next=https://malicious.example/profile/")

        self.assertEqual(response.status_code, 302)
        self.assertIn("accounts.google.com", response["Location"])
        self.assertIsNone(client.session.get("auth_next"))


class EmployerVerificationMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_employer_role_on_user_is_restricted_even_if_profile_role_stale(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.middleware.employer_verification import EmployerVerificationMiddleware

        request = self.factory.get(reverse("view_posted_jobs"))
        request.user = SimpleNamespace(
            is_authenticated=True,
            role="employer",
            profile=SimpleNamespace(role="applicant"),
            employer_company=None,
        )

        middleware = EmployerVerificationMiddleware(lambda req: None)
        with patch("core.middleware.employer_verification.messages.warning"):
            response = middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("complete_employer_profile"))

    def test_unverified_employer_is_redirected_to_upload_docs(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.middleware.employer_verification import EmployerVerificationMiddleware

        company = SimpleNamespace(is_complete=True, is_verified=False)
        request = self.factory.get(reverse("view_posted_jobs"))
        request.user = SimpleNamespace(
            is_authenticated=True,
            role="employer",
            profile=SimpleNamespace(role="employer"),
            employer_company=company,
        )

        middleware = EmployerVerificationMiddleware(lambda req: None)
        with patch("core.middleware.employer_verification.messages.warning"):
            response = middleware(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("upload_company_docs"))


class RoleGuardTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _build_request(self, path):
        request = self.factory.get(path)

        session_middleware = SessionMiddleware(lambda req: None)
        session_middleware.process_request(request)
        setattr(request, "_messages", FallbackStorage(request))
        return request

    def test_get_effective_role_prefers_profile_role(self):
        from types import SimpleNamespace

        user = SimpleNamespace(role="employer", profile=SimpleNamespace(role="applicant"))
        self.assertEqual(_get_effective_role(user), "applicant")

    def test_view_posted_jobs_blocks_applicant_with_employer_user_role(self):
        from types import SimpleNamespace

        request = self._build_request(reverse("view_posted_jobs"))
        request.user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            role="employer",
            profile=SimpleNamespace(role="applicant"),
        )

        response = view_posted_jobs(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))
