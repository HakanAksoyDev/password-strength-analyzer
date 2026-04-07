import unittest

from fastapi import HTTPException

from app import MAX_PASSWORD_LENGTH, AnalyzeRequest, analyze_password, health, index
from src.analyzer import analyze


class AppEndpointsTestCase(unittest.TestCase):
    def test_index_route_points_to_ui_file(self):
        response = index()
        self.assertTrue(str(response.path).endswith("public/index.html"))

    def test_health_route(self):
        body = health()
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["service"], "password-strength-analyzer")

    def test_analyze_route_success(self):
        body = analyze_password(AnalyzeRequest(password="Str0ng!Pass1"))
        self.assertIn("score", body)
        self.assertIn("label", body)
        self.assertIn("reasons", body)
        self.assertIn("suggestions", body)
        self.assertIn("details", body)

    def test_analyze_route_rejects_too_long_password(self):
        with self.assertRaises(HTTPException) as ctx:
            analyze_password(AnalyzeRequest(password="a" * (MAX_PASSWORD_LENGTH + 1)))
        self.assertEqual(ctx.exception.status_code, 400)


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
