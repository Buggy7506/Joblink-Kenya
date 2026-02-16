from datetime import timedelta
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from core.views import (
    _get_effective_role,
    _normalize_next_url,
    complete_employer_profile,
    chat_view,
    view_posted_jobs,
)


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

    def test_async_stack_uses_request_auser_and_returns_async_response(self):
        import asyncio
        from types import SimpleNamespace

        from core.middleware.employer_verification import EmployerVerificationMiddleware

        request = self.factory.get(reverse("dashboard"))

        async def auser():
            return SimpleNamespace(is_authenticated=False)

        request.auser = auser

        async def get_response(req):
            return SimpleNamespace(status_code=200)

        middleware = EmployerVerificationMiddleware(get_response)
        response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 200)


class RoleGuardTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _build_request(self, path):
        request = self.factory.get(path)

        session_middleware = SessionMiddleware(lambda req: None)
        session_middleware.process_request(request)
        setattr(request, "_messages", FallbackStorage(request))
        return request

    def test_get_effective_role_prefers_user_role_when_mismatched(self):
        from types import SimpleNamespace

        user = SimpleNamespace(role="employer", profile=SimpleNamespace(role="applicant"))
        self.assertEqual(_get_effective_role(user), "employer")

    def test_view_posted_jobs_blocks_non_employer_when_profile_is_stale(self):
        from types import SimpleNamespace

        request = self._build_request(reverse("view_posted_jobs"))
        request.user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            role="applicant",
            profile=SimpleNamespace(role="employer"),
        )

        response = view_posted_jobs(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))

    def test_complete_employer_profile_allows_employer_user_role_when_profile_missing(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        request = self._build_request(reverse("complete_employer_profile"))
        request.method = "GET"
        request.user = SimpleNamespace(
            is_authenticated=True,
            role="employer",
        )

        with patch("core.views.EmployerCompany.objects.filter") as mock_filter, patch(
            "core.views.render"
        ) as mock_render:
            mock_filter.return_value.first.return_value = None
            mock_render.return_value = SimpleNamespace(status_code=200)

            response = complete_employer_profile.__wrapped__.__wrapped__(request)

        self.assertEqual(response.status_code, 200)
        mock_render.assert_called_once()

    def test_complete_employer_profile_falls_back_when_broker_unavailable(self):
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch

        from django.core.files.uploadedfile import SimpleUploadedFile
        from django.test import override_settings
        from kombu.exceptions import OperationalError as KombuOperationalError

        request = self._build_request(reverse("complete_employer_profile"))
        request.method = "POST"
        request.POST = {
            "document_type": "incorporation",
        }
        request.FILES["file"] = SimpleUploadedFile("company.pdf", b"test-file", content_type="application/pdf")
        request.user = SimpleNamespace(
            is_authenticated=True,
            id=42,
            role="employer",
        )

        company_obj = SimpleNamespace(user=request.user, is_verified=False)
        company_obj.save = lambda: None
        company_obj.refresh_from_db = lambda: None

        company_form = SimpleNamespace(
            is_valid=lambda: True,
            save=lambda commit=False: company_obj,
        )
        doc_form = SimpleNamespace(
            is_valid=lambda: True,
            cleaned_data={"document_type": "incorporation"},
        )

        with tempfile.TemporaryDirectory() as temp_media_root, override_settings(MEDIA_ROOT=temp_media_root), patch(
            "core.views.EmployerCompany.objects.filter"
        ) as mock_filter, patch("core.views.EmployerCompanyForm", return_value=company_form), patch(
            "core.views.CompanyDocumentForm", return_value=doc_form
        ), patch("core.views.redirect", return_value=SimpleNamespace(status_code=302)) as mock_redirect, patch(
            "core.views.save_employer_document.delay",
            side_effect=KombuOperationalError("connection refused"),
        ), patch("core.views.save_employer_document.apply") as mock_apply:
            mock_filter.return_value.first.return_value = None

            response = complete_employer_profile.__wrapped__.__wrapped__(request)

        self.assertEqual(response.status_code, 302)
        mock_apply.assert_called_once()
        mock_redirect.assert_called_with("complete_employer_profile")

class ProxyHeaderNormalizeMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_x_forwarded_headers_are_normalized_to_first_value(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_PROTO"] = "https,http"
        request.META["HTTP_X_FORWARDED_HOST"] = "stepper.dpdns.org,internal.render"

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")
        self.assertEqual(request.META["HTTP_X_FORWARDED_HOST"], "stepper.dpdns.org")

    def test_cf_visitor_https_overrides_proto_to_prevent_loops(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_PROTO"] = "http"
        request.META["HTTP_CF_VISITOR"] = '{"scheme":"https"}'

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")

    def test_forwarded_header_https_overrides_proto_to_prevent_loops(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_PROTO"] = "http"
        request.META["HTTP_FORWARDED"] = "for=203.0.113.43;proto=https;host=stepper.dpdns.org"

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")

    def test_x_forwarded_ssl_on_sets_https(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_PROTO"] = "http"
        request.META["HTTP_X_FORWARDED_SSL"] = "on"

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")

    def test_cloudfront_forwarded_proto_sets_https(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_CLOUDFRONT_FORWARDED_PROTO"] = "https"

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")

    def test_x_forwarded_scheme_fallback_sets_https(self):
        from core.middleware.proxy_fix import ProxyHeaderNormalizeMiddleware

        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_SCHEME"] = "https"

        middleware = ProxyHeaderNormalizeMiddleware(lambda req: req)
        middleware(request)

        self.assertEqual(request.META["HTTP_X_FORWARDED_PROTO"], "https")

class GoogleRoleSelectionTests(TestCase):
    def test_google_choose_role_persists_role_for_set_password_step(self):
        session = self.client.session
        session["oauth_user"] = {
            "email": "new.user@example.com",
            "first_name": "New",
            "last_name": "User",
            "provider": "google",
        }
        session.save()

        response = self.client.post(reverse("google_choose_role"), {"role": "employer"})

        self.assertRedirects(response, reverse("set_google_password"))
        self.assertEqual(self.client.session.get("oauth_role"), "employer")
        self.assertEqual(self.client.session.get("oauth_user", {}).get("role"), "employer")


class GoogleCallbackProfilePictureSyncTests(TestCase):
    def test_existing_google_user_syncs_latest_profile_picture(self):
        from unittest.mock import Mock, patch

        from core.models import CustomUser

        user = CustomUser.objects.create_user(
            username="existing-google-user",
            email="existing.google@example.com",
            password="StrongPass123",
            role="applicant",
        )

        with patch("core.views.requests.post") as mock_post, patch(
            "core.views.requests.get"
        ) as mock_get, patch("core.views._sync_oauth_profile_picture", return_value=True) as mock_sync:
            mock_post.return_value = Mock(json=lambda: {"access_token": "token-123"})
            mock_get.return_value = Mock(
                json=lambda: {
                    "email": "existing.google@example.com",
                    "given_name": "Existing",
                    "family_name": "Google",
                    "picture": "https://example.com/new-google-avatar.jpg",
                }
            )

            response = self.client.get(reverse("google_callback"), {"code": "auth-code"})

        self.assertEqual(response.status_code, 302)
        mock_sync.assert_called_once_with(
            user,
            "https://example.com/new-google-avatar.jpg",
            provider="google",
        )


class ExpiredJobCleanupMiddlewareTests(SimpleTestCase):
    def test_middleware_deletes_expired_jobs_on_each_request(self):
        from unittest.mock import patch

        from core.middleware.job_expiry_cleanup import ExpiredJobCleanupMiddleware

        request = RequestFactory().get("/")
        middleware = ExpiredJobCleanupMiddleware(lambda req: None)

        with patch("core.middleware.job_expiry_cleanup.Job.objects.filter") as mock_filter:
            middleware(request)

        mock_filter.assert_called_once()
        mock_filter.return_value.delete.assert_called_once()

    def test_async_stack_awaits_async_get_response(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.middleware.job_expiry_cleanup import ExpiredJobCleanupMiddleware

        request = RequestFactory().get("/")

        async def get_response(req):
            return SimpleNamespace(status_code=200)

        middleware = ExpiredJobCleanupMiddleware(get_response)

        with patch("core.middleware.job_expiry_cleanup.Job.objects.filter") as mock_filter:
            response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 200)
        mock_filter.assert_called_once()
        mock_filter.return_value.delete.assert_called_once()


class SuppressProbeNoiseFilterTests(SimpleTestCase):
    def test_filter_blocks_known_probe_message(self):
        import logging

        from core.logging_filters import SuppressProbeNoiseFilter

        log_record = logging.LogRecord(
            name="django.request",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="Not Found: /.git/HEAD",
            args=(),
            exc_info=None,
        )

        self.assertFalse(SuppressProbeNoiseFilter().filter(log_record))

    def test_filter_allows_non_probe_warning(self):
        import logging

        from core.logging_filters import SuppressProbeNoiseFilter

        log_record = logging.LogRecord(
            name="django.request",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="Not Found: /jobs/some-slug",
            args=(),
            exc_info=None,
        )

        self.assertTrue(SuppressProbeNoiseFilter().filter(log_record))

class SuppressAsyncCancelNoiseFilterTests(SimpleTestCase):
    def test_filter_blocks_asgiref_cancelled_error_noise(self):
        import logging

        from core.logging_filters import SuppressAsyncCancelNoiseFilter

        log_record = logging.LogRecord(
            name="asgiref.sync",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="CancelledError exception in shielded future",
            args=(),
            exc_info=None,
        )

        self.assertFalse(SuppressAsyncCancelNoiseFilter().filter(log_record))

    def test_filter_allows_unrelated_asgiref_errors(self):
        import logging

        from core.logging_filters import SuppressAsyncCancelNoiseFilter

        log_record = logging.LogRecord(
            name="asgiref.sync",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="Unhandled exception while running sync adapter",
            args=(),
            exc_info=None,
        )

        self.assertTrue(SuppressAsyncCancelNoiseFilter().filter(log_record))


class ChatViewAuthGuardTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_chat_view_redirects_anonymous_user_to_login(self):
        request = self.factory.get("/chat/job/3/")
        request.user = AnonymousUser()

        response = chat_view(request, job_id=3)

        self.assertEqual(response.status_code, 302)
        self.assertIn("/Sign-In-OR-Sign-Up/", response.url)
        self.assertIn("next=/chat/job/3/", response.url)
