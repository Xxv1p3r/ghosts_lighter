# -*- coding: utf-8 -*-
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ghosts_lighter.scanners.sqli import SQLiScanner, SQL_ERROR_PATTERNS
from ghosts_lighter.scanners.xss import XSSScanner, analyze_reflection_context
from ghosts_lighter.scanners.traversal import TraversalScanner, check_php_base64_disclosure


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

    def test_traversal_linux_detection(self):
        # Endpoint vulnerable a LFI Linux (/etc/passwd)
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "etc/passwd" in val:
                return MockResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", 200)
            return MockResponse("Welcome home", 200)

        mock_session = MockSession(handler)
        scanner = TraversalScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/view", "file")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['target_os'], 'Linux')

    def test_traversal_windows_detection(self):
        # Endpoint vulnerable a LFI Windows (win.ini)
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "win.ini" in val:
                return MockResponse("; for 16-bit app support\n[fonts]\n[extensions]", 200)
            return MockResponse("Normal view", 200)

        mock_session = MockSession(handler)
        scanner = TraversalScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/load", "page")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['target_os'], 'Windows')

    def test_traversal_php_wrapper_detection(self):
        # Endpoint vulnerable a PHP wrapper Base64 disclosure
        import base64
        php_code = "<?php\n$db_pass = 'super_secret_123';\nfunction connect() {}\n?>"
        encoded_b64 = base64.b64encode(php_code.encode()).decode()

        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "php://filter" in val:
                return MockResponse(f"File content: {encoded_b64}", 200)
            return MockResponse("Regular page", 200)

        mock_session = MockSession(handler)
        scanner = TraversalScanner(mock_session)
        findings = scanner.scan_endpoint("http://example.local/index.php", "page")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertIn("wrapper PHP", findings[0]['detalle'])


if __name__ == '__main__':
    unittest.main()
