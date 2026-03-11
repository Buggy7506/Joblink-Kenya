from datetime import timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from core.aggregator.service import JobAggregationService
from core.aggregator.sources import NormalizedJob
from core.models import AggregatedJobRecord, Job, Profile
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


class EmployerVerificationMiddlewareAsyncDBTests(TestCase):
    def test_async_stack_handles_profile_relation_without_sync_only_error(self):
        import asyncio
        from types import SimpleNamespace

        from core.middleware.employer_verification import EmployerVerificationMiddleware

        user_model = get_user_model()
        user = user_model.objects.create_user(
            username="async-employer-mw",
            email="async-employer-mw@example.com",
            password="testpass123",
            role="applicant",
        )
        Profile.objects.update_or_create(
            user=user,
            defaults={"role": "applicant"},
        )

        request = RequestFactory().get(reverse("dashboard"))

        async def auser():
            return user

        async def get_response(req):
            return SimpleNamespace(status_code=200)

        request.auser = auser
        request.user = user

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




class MicrosoftCallbackProfilePictureSyncTests(TestCase):
    def test_existing_microsoft_user_syncs_latest_profile_picture(self):
        from unittest.mock import Mock, patch

        from core.models import CustomUser

        user = CustomUser.objects.create_user(
            username="existing-microsoft-user",
            email="existing.microsoft@example.com",
            password="StrongPass123",
            role="applicant",
        )

        with patch("core.views.requests.post") as mock_post, patch(
            "core.views.requests.get"
        ) as mock_get, patch("core.views._sync_profile_picture_to_profile", return_value=True) as mock_mirror:
            mock_post.return_value = Mock(json=lambda: {"access_token": "token-123"})

            graph_response = Mock()
            graph_response.json.return_value = {
                "mail": "existing.microsoft@example.com",
                "givenName": "Existing",
                "surname": "Microsoft",
            }

            photo_response = Mock()
            photo_response.status_code = 200
            photo_response.content = b"microsoft-photo-bytes"
            photo_response.headers = {"Content-Type": "image/png"}
            mock_get.side_effect = [graph_response, photo_response]

            response = self.client.get(reverse("microsoft_callback"), {"code": "auth-code"})

        self.assertEqual(response.status_code, 302)
        user.refresh_from_db()
        self.assertIn("_microsoft.png", user.profile_pic.name)
        mock_mirror.assert_called_once_with(user)


class MicrosoftPhotoFetchHelperTests(SimpleTestCase):
    def test_fetch_microsoft_profile_photo_returns_bytes_and_extension(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.views import _fetch_microsoft_profile_photo

        with patch("core.views.requests.get") as mock_get:
            mock_get.return_value = SimpleNamespace(
                status_code=200,
                content=b"photo-bytes",
                headers={"Content-Type": "image/png"},
            )

            photo_bytes, extension = _fetch_microsoft_profile_photo({"Authorization": "Bearer token"})

        self.assertEqual(photo_bytes, b"photo-bytes")
        self.assertEqual(extension, "png")

    def test_fetch_microsoft_profile_photo_handles_missing_photo(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.views import _fetch_microsoft_profile_photo

        with patch("core.views.requests.get") as mock_get:
            mock_get.return_value = SimpleNamespace(status_code=404, content=b"", headers={})

            photo_bytes, extension = _fetch_microsoft_profile_photo({"Authorization": "Bearer token"})

        self.assertIsNone(photo_bytes)
        self.assertEqual(extension, "jpg")

class ExpiredJobCleanupMiddlewareTests(TestCase):
    def test_middleware_deletes_expired_jobs_on_each_request(self):
        from unittest.mock import patch

        from core.middleware.job_expiry_cleanup import ExpiredJobCleanupMiddleware

        request = RequestFactory().get("/")
        middleware = ExpiredJobCleanupMiddleware(lambda req: None)

        with patch("core.middleware.job_expiry_cleanup.Job.objects.filter") as mock_filter:
            middleware(request)

        mock_filter.assert_called_once()
        mock_filter.return_value.delete.assert_called_once()

    
    def test_async_stack_runs_db_cleanup_without_sync_only_error(self):
        import asyncio
        from types import SimpleNamespace

        from core.middleware.job_expiry_cleanup import ExpiredJobCleanupMiddleware

        request = RequestFactory().get("/")

        async def get_response(req):
            return SimpleNamespace(status_code=200)

        middleware = ExpiredJobCleanupMiddleware(get_response)
        response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 200)
        
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

    def test_async_stack_ignores_cancelled_cleanup_and_returns_response(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.middleware.job_expiry_cleanup import ExpiredJobCleanupMiddleware

        request = RequestFactory().get("/")

        async def get_response(req):
            return SimpleNamespace(status_code=200)

        async def cancelled_cleanup():
            raise asyncio.CancelledError

        def fake_sync_to_async(*args, **kwargs):
            def runner():
                return cancelled_cleanup()

            return runner

        middleware = ExpiredJobCleanupMiddleware(get_response)

        with patch("core.middleware.job_expiry_cleanup.sync_to_async", side_effect=fake_sync_to_async):
            response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 200)


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




class ChatViewNavigationTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.employer = user_model.objects.create_user(
            username="nav-employer",
            email="nav-employer@example.com",
            password="testpass123",
            role="employer",
        )
        self.applicant = user_model.objects.create_user(
            username="nav-applicant",
            email="nav-applicant@example.com",
            password="testpass123",
            role="applicant",
        )

    def test_applicant_group_link_keeps_application_id_for_back_navigation(self):
        from core.models import Application, Job

        job = Job.objects.create(
            title="Mobile Bug",
            description="Fix back navigation",
            location="Nairobi",
            employer=self.employer,
        )
        application = Application.objects.create(job=job, applicant=self.applicant)

        self.client.force_login(self.applicant)
        response = self.client.get(reverse("job_chat", args=[application.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            f"{reverse('chat_job_applicants')}?job_id={job.id}&application_id={application.id}",
        )

class RequestShieldMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_sync_stack_allows_normal_request(self):
        from core.middleware.request_shield import RequestShieldMiddleware

        request = self.factory.get('/chat/job/3/')
        request.META['REMOTE_ADDR'] = '127.0.0.10'

        middleware = RequestShieldMiddleware(lambda req: HttpResponse('ok'))
        response = middleware(request)

        self.assertEqual(response.status_code, 200)

    def test_async_stack_awaits_downstream_response(self):
        import asyncio

        from core.middleware.request_shield import RequestShieldMiddleware

        request = self.factory.get('/chat/job/3/')
        request.META['REMOTE_ADDR'] = '127.0.0.11'

        async def get_response(req):
            return HttpResponse('ok')

        middleware = RequestShieldMiddleware(get_response)
        response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 200)

    def test_async_stack_blocks_probe_path_without_await_errors(self):
        import asyncio

        from core.middleware.request_shield import RequestShieldMiddleware

        request = self.factory.get('/.env')
        request.META['REMOTE_ADDR'] = '127.0.0.12'

        async def get_response(req):
            return HttpResponse('ok')

        middleware = RequestShieldMiddleware(get_response)
        response = asyncio.run(middleware(request))

        self.assertEqual(response.status_code, 404)


class OAuthProfilePictureMirrorTests(SimpleTestCase):
    def test_sync_profile_picture_to_profile_updates_profile_picture_field(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        from core.views import _sync_profile_picture_to_profile

        profile = SimpleNamespace(profile_pic=None, save=Mock())
        uploaded_picture = SimpleNamespace(url="https://example.com/pic.jpg")
        user = SimpleNamespace(pk=42, profile=profile, profile_pic=uploaded_picture)

        with patch("core.views.Profile.objects.get_or_create", return_value=(profile, False)) as mock_get_or_create:
            synced = _sync_profile_picture_to_profile(user)

        self.assertTrue(synced)
        self.assertEqual(profile.profile_pic, uploaded_picture)
        mock_get_or_create.assert_called_once()
        profile.save.assert_called_once_with(update_fields=["profile_pic"])

    def test_sync_oauth_profile_picture_calls_profile_mirror_on_success(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        from core.views import _sync_oauth_profile_picture

        class EmptyProfilePicField:
            def __init__(self):
                self.save = Mock()

            def __bool__(self):
                return False

        user = SimpleNamespace(
            pk=7,
            id=7,
            username="google-user",
            email="google@example.com",
            profile_pic=EmptyProfilePicField(),
        )

        with patch("core.views.requests.get") as mock_get, patch(
            "core.views._sync_profile_picture_to_profile", return_value=True
        ) as mock_profile_sync:
            mock_get.return_value = SimpleNamespace(
                status_code=200,
                content=b"image-bytes",
                headers={"Content-Type": "image/jpeg"},
            )

            synced = _sync_oauth_profile_picture(
                user,
                "https://example.com/new-avatar.jpg",
                provider="google",
            )

        self.assertTrue(synced)
        user.profile_pic.save.assert_called_once()
        mock_profile_sync.assert_called_once_with(user)

    def test_sync_oauth_profile_picture_refreshes_existing_google_picture(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch

        from core.views import _sync_oauth_profile_picture

        existing_profile_pic = SimpleNamespace(url="https://example.com/existing.jpg", save=Mock())
        user = SimpleNamespace(
            pk=8,
            id=8,
            username="existing-google-user",
            email="existing.google@example.com",
            profile_pic=existing_profile_pic,
        )

        with patch("core.views.requests.get") as mock_get, patch(
            "core.views._sync_profile_picture_to_profile", return_value=True
        ) as mock_profile_sync:
            mock_get.return_value = SimpleNamespace(
                status_code=200,
                content=b"new-google-image-bytes",
                headers={"Content-Type": "image/jpeg"},
            )
            synced = _sync_oauth_profile_picture(
                user,
                "https://example.com/new-avatar.jpg",
                provider="google",
            )

        self.assertTrue(synced)
        mock_get.assert_called_once()
        existing_profile_pic.save.assert_called_once()
        mock_profile_sync.assert_called_once_with(user)

    def test_sync_oauth_profile_picture_preserves_existing_non_google_picture(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.views import _sync_oauth_profile_picture

        user = SimpleNamespace(
            pk=9,
            id=9,
            username="existing-microsoft-user",
            email="existing.microsoft@example.com",
            profile_pic=SimpleNamespace(url="https://example.com/existing.jpg"),
        )

        with patch("core.views.requests.get") as mock_get, patch(
            "core.views._sync_profile_picture_to_profile", return_value=True
        ) as mock_profile_sync:
            synced = _sync_oauth_profile_picture(
                user,
                "https://example.com/new-avatar.jpg",
                provider="microsoft",
            )

        self.assertTrue(synced)
        mock_get.assert_not_called()
        mock_profile_sync.assert_called_once_with(user)

class UserRoleInterdependencySignalTests(SimpleTestCase):
    def test_employer_company_created_when_user_role_is_employer(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.signals import create_employer_company

        user = SimpleNamespace(role="employer", profile=SimpleNamespace(role="applicant"))

        with patch("core.signals.EmployerCompany.objects.get_or_create") as mock_get_or_create:
            create_employer_company(sender=None, instance=user, created=True)

        mock_get_or_create.assert_called_once_with(user=user)

    def test_employer_company_created_when_profile_role_is_employer_and_user_role_stale(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from core.signals import create_employer_company

        user = SimpleNamespace(role="applicant", profile=SimpleNamespace(role="employer"))

        with patch("core.signals.EmployerCompany.objects.get_or_create") as mock_get_or_create:
            create_employer_company(sender=None, instance=user, created=False)

        mock_get_or_create.assert_called_once_with(user=user)


class AggregationServiceTests(TestCase):
    def test_ingest_creates_and_updates_aggregated_jobs(self):
        service = JobAggregationService(system_username="test-aggregator")
        initial = [
            NormalizedJob(
                title="Backend Engineer",
                company="Acme",
                location="Nairobi",
                description="Build APIs",
                apply_url="https://example.com/apply/1",
                source="remotive",
                source_job_id="1",
                source_url="https://example.com/jobs/1",
            )
        ]

        first = service.ingest(initial)
        self.assertEqual(first.created, 1)

        record = AggregatedJobRecord.objects.get(source="remotive", source_job_id="1")
        self.assertEqual(record.job.title, "Backend Engineer")

        updated = [
            NormalizedJob(
                title="Senior Backend Engineer",
                company="Acme",
                location="Nairobi",
                description="Build APIs and data pipelines",
                apply_url="https://example.com/apply/1",
                source="remotive",
                source_job_id="1",
                source_url="https://example.com/jobs/1",
            )
        ]
        second = service.ingest(updated)
        self.assertEqual(second.updated, 1)

        record.refresh_from_db()
        self.assertEqual(record.job.title, "Senior Backend Engineer")


    def test_ingest_maps_category_salary_and_logo_payload(self):
        service = JobAggregationService(system_username="test-aggregator-meta")
        payload_item = NormalizedJob(
            title="Frontend Developer",
            company="Acme Labs",
            location="Nairobi",
            description="Salary KES 120000 monthly",
            apply_url="https://example.com/apply/2",
            source="remotive",
            source_job_id="2",
            metadata={
                "category": "Engineering",
                "salary": "KES 120000",
                "company_logo_url": "https://example.com/logo.png",
            },
        )

        result = service.ingest([payload_item])
        self.assertEqual(result.created, 1)

        record = AggregatedJobRecord.objects.get(source="remotive", source_job_id="2")
        self.assertEqual(record.job.company, "Acme Labs")
        self.assertEqual(record.job.location, "Nairobi")
        self.assertEqual(record.job.salary, 120000)
        self.assertEqual(record.job.category.name, "Engineering")
        self.assertEqual(record.payload.get("company_logo_url"), "https://example.com/logo.png")

class ExternalAggregatedApplyFlowTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.applicant = user_model.objects.create_user(
            username="applicant-agg",
            email="applicant-agg@example.com",
            password="testpass123",
            role="applicant",
        )
        Profile.objects.update_or_create(user=self.applicant, defaults={"role": "applicant"})

        self.employer = user_model.objects.create_user(
            username="agg-employer",
            email="agg-employer@example.com",
            password="testpass123",
            role="employer",
        )

        self.job = Job.objects.create(
            title="Data Engineer",
            description="Pipeline work",
            location="Remote",
            employer=self.employer,
            company="Source Corp",
        )
        AggregatedJobRecord.objects.create(
            job=self.job,
            source="remotive",
            source_job_id="rem-100",
            apply_url="https://example.com/apply/rem-100",
            source_url="https://example.com/jobs/rem-100",
            fingerprint="abc123def456ghi789jkl012mno345pqrs678tuv901wxy234zab567cde890",
        )

    def test_apply_job_redirects_to_external_source_for_aggregated_job(self):
        self.client.login(username="applicant-agg", password="testpass123")
        response = self.client.post(reverse("apply_job", args=[self.job.id]))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://example.com/apply/rem-100")


class AggregationMaintenanceTests(TestCase):
    def test_deactivate_stale_jobs_marks_job_inactive(self):
        service = JobAggregationService(system_username="test-aggregator-stale")
        service.ingest(
            [
                NormalizedJob(
                    title="Platform Engineer",
                    company="Acme",
                    location="Remote",
                    description="Infra",
                    apply_url="https://example.com/apply/platform",
                    source="remotive",
                    source_job_id="stale-1",
                )
            ]
        )

        record = AggregatedJobRecord.objects.get(source="remotive", source_job_id="stale-1")
        AggregatedJobRecord.objects.filter(pk=record.pk).update(
            last_seen_at=timezone.now() - timedelta(hours=120)
        )

        deactivated = service.deactivate_stale_jobs(source="remotive", stale_hours=48)
        self.assertEqual(deactivated, 1)

        record.refresh_from_db()
        self.assertFalse(record.is_live)
        self.assertFalse(record.job.is_active)


class SourceRegistryTests(SimpleTestCase):
    def test_registry_contains_requested_source_keys(self):
        from core.aggregator.sources import ADAPTER_REGISTRY, CONFIGURABLE_JSON_SOURCES

        required = {
            "remotive", "arbeitnow", "adzuna", "jooble", "remoteok", "weworkremotely",
            "greenhouse", "lever", "ashby", "smartrecruiters", "workable", "bamboohr",
            "personio", "recruitee", "jobicy", "remotewx", "ycombinator", "wellfound",
            "remotive_api", "usajobs", "remotive_global",
        }
        available = set(ADAPTER_REGISTRY.keys()) | set(CONFIGURABLE_JSON_SOURCES.keys())
        self.assertTrue(required.issubset(available))

    def test_get_source_adapters_respects_settings(self):
        from django.test import override_settings

        from core.aggregator.sources import get_source_adapters

        with override_settings(JOB_AGGREGATOR_ENABLED_SOURCES=("arbeitnow",)):
            adapters = get_source_adapters()

        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].source_name, "arbeitnow")


class AggregationCommandTests(SimpleTestCase):
    def test_list_job_aggregator_sources_command_shows_enabled(self):
        from io import StringIO
        from django.core.management import call_command
        from django.test import override_settings

        out = StringIO()
        with override_settings(JOB_AGGREGATOR_ENABLED_SOURCES=("remotive",)):
            call_command("list_job_aggregator_sources", stdout=out)

        output = out.getvalue()
        self.assertIn("remotive (enabled)", output)
        self.assertIn("arbeitnow (disabled)", output)
