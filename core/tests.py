from django.test import Client, RequestFactory, SimpleTestCase, TestCase

from core.views import _normalize_next_url


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
