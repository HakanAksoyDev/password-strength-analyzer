import unittest

from fastapi.testclient import TestClient

from app import MAX_PASSWORD_LENGTH, app
from src.analyzer import analyze


class AppEndpointsTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_index_route_serves_ui(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password Strength Analyzer", response.text)

    def test_health_route(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["ok"], True)
        self.assertEqual(response.headers.get("cache-control"), "no-store, max-age=0")

    def test_analyze_route_success(self):
        response = self.client.post("/api/analyze", json={"password": "Str0ng!Pass1"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("score", body)
        self.assertIn("label", body)
        self.assertIn("reasons", body)
        self.assertIn("suggestions", body)
        self.assertIn("details", body)

    def test_analyze_route_rejects_non_string(self):
        response = self.client.post("/api/analyze", json={"password": 12345})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get("detail"), "`password` must be a string.")

    def test_analyze_route_rejects_too_long_password(self):
        response = self.client.post(
            "/api/analyze",
            json={"password": "a" * (MAX_PASSWORD_LENGTH + 1)},
        )
        self.assertEqual(response.status_code, 400)


class AnalyzerTestCase(unittest.TestCase):
    def test_common_password_score_is_capped(self):
        result = analyze("password")
        self.assertLessEqual(result["score"], 25)
        self.assertEqual(result["label"], "Weak")

    def test_suggestions_are_deduplicated(self):
        result = analyze("passwordpassword")
        self.assertEqual(len(result["suggestions"]), len(set(result["suggestions"])))


if __name__ == "__main__":
    unittest.main()
