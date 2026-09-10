# -*- coding: utf-8 -*-
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ghosts_lighter.scanners.sqli import SQLiScanner, SQL_ERROR_PATTERNS
from ghosts_lighter.scanners.xss import XSSScanner, analyze_reflection_context


class MockResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html; charset=utf-8'}


class MockSession:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, params=None, timeout=None, **kwargs):
        return self.handler(url, params)


class TestSQLiAndXSSScanners(unittest.TestCase):
    def test_sql_error_patterns(self):
        # Verificar detección de firmas de error
        mysql_err = "Warning: mysql_fetch_array() expects parameter 1 to be resource"
        pg_err = "ERROR: syntax error at or near 'admin'"
        sqlite_err = "SQLite3::SQLException: unrecognized token"

        matches = []
        for pattern, db in SQL_ERROR_PATTERNS:
            if pattern.search(mysql_err):
                matches.append(db)
        self.assertIn("MySQL / MariaDB", matches)

        matches_pg = []
        for pattern, db in SQL_ERROR_PATTERNS:
            if pattern.search(pg_err):
                matches_pg.append(db)
        self.assertIn("PostgreSQL", matches_pg)

    def test_xss_context_detection(self):
        # Body context
        html_body = "<div>Hello glxss7\"'>{ world</div>"
        ctx, _ = analyze_reflection_context(html_body, "glxss7\"'>{")
        self.assertEqual(ctx, 'BODY')

        # Double quoted attribute context
        html_attr_double = '<input type="text" value="glxss7\"\'>{" name="q">'
        ctx, _ = analyze_reflection_context(html_attr_double, "glxss7\"'>{")
        self.assertEqual(ctx, 'ATTR_DOUBLE')

        # Single quoted attribute context
        html_attr_single = "<input type='text' value='glxss7\"\'>{' name='q'>"
        ctx, _ = analyze_reflection_context(html_attr_single, "glxss7\"'>{")
        self.assertEqual(ctx, 'ATTR_SINGLE')

        # Script context
        html_script = "<script>var user = 'glxss7\"'>{';</script>"
        ctx, _ = analyze_reflection_context(html_script, "glxss7\"'>{")
        self.assertEqual(ctx, 'SCRIPT')

        # Comment context
        html_comment = "<!-- User comment: glxss7\"'>{ -->"
        ctx, _ = analyze_reflection_context(html_comment, "glxss7\"'>{")
        self.assertEqual(ctx, 'COMMENT')

    def test_xss_sanitized_no_finding(self):
        # Si la entrada se codifica adecuadamente con HTML entities, no debe alertar
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            import html
            safe_val = html.escape(val)
            return MockResponse(f"<div>Result: {safe_val}</div>")

        mock_session = MockSession(handler)
        scanner = XSSScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/search", "q")
        # No debe haber hallazgos críticos porque los caracteres están codificados
        self.assertEqual(len(findings), 0)

    def test_xss_vulnerable_body(self):
        # Endpoint vulnerable donde la entrada se refleja sin escapar en el body
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            return MockResponse(f"<div>Result: {val}</div>")

        mock_session = MockSession(handler)
        scanner = XSSScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/search", "q")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')

    def test_sqli_error_based_detection(self):
        # Endpoint vulnerable a error-based SQLi
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "'" in val:
                return MockResponse("Fatal error: You have an error in your SQL syntax near '' at line 1", 200)
            return MockResponse("OK Normal Page", 200)

        mock_session = MockSession(handler)
        scanner = SQLiScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/item", "id")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['technique'], 'Error-Based')


if __name__ == '__main__':
    unittest.main()
