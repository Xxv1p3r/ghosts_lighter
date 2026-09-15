# -*- coding: utf-8 -*-
import unittest
import sys
import os
import re
import json
import time
import base64
import hashlib
import hmac

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ghosts_lighter.scanners.sqli import SQLiScanner, SQL_ERROR_PATTERNS
from ghosts_lighter.scanners.xss import XSSScanner, analyze_reflection_context
from ghosts_lighter.scanners.traversal import TraversalScanner, check_php_base64_disclosure
from ghosts_lighter.scanners.ssrf import SSRFScanner
from ghosts_lighter.scanners.ssti import SSTIScanner
from ghosts_lighter.scanners.cmdi import CommandInjectionScanner
from ghosts_lighter.scanners.graphql import GraphQLIntrospectionScanner
from ghosts_lighter.scanners.bypass403 import AccessControl403Scanner
from ghosts_lighter.scanners.jwt import JWTScanner, es_jwt, extraer_jwts
from ghosts_lighter.scanners.idor import IDORScanner, IDOR_PARAM_HINTS
import ghosts_lighter.scanners.cmdi as cmdi


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

    def post(self, url, json=None, timeout=None, **kwargs):
        query = json.get('query') if isinstance(json, dict) else None
        return self.handler(url, {'query': query})


class MockBypassSession:
    """Sesion que expone metodo HTTP y cabeceras al handler: handler(method, url, headers)."""
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, params=None, timeout=None, **kwargs):
        return self.handler('GET', url, kwargs.get('headers') or {})

    def request(self, method, url, timeout=None, **kwargs):
        return self.handler(method, url, kwargs.get('headers') or {})


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


class TestSSRFScanner(unittest.TestCase):
    def test_cloud_metadata_detection(self):
        # Endpoint que resuelve URLs server-side y expone metadatos de nube
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "169.254.169.254/latest/meta-data" in val:
                return MockResponse("ami-id\ninstance-id\nlocal-hostname\nplacement/availability-zone")
            return MockResponse("Recurso no encontrado", 404)

        scanner = SSRFScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/fetch", "url")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertIn("Cloud Metadata", findings[0]['technique'])
        self.assertEqual(findings[0]['cwe'], 'CWE-918')

    def test_reflected_payload_is_not_a_finding(self):
        # El endpoint refleja la URL recibida pero no la resuelve: no debe alertar
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            return MockResponse(f"<div>No se pudo cargar la URL: {val}</div>")

        scanner = SSRFScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/proxy", "url")
        self.assertEqual(len(findings), 0)

    def test_internal_service_differential(self):
        # El loopback responde con contenido distinto al de un host inexistente
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if "127.0.0.1" in val:
                return MockResponse("Panel interno de administracion " + "X" * 200)
            return MockResponse("Error al resolver el recurso solicitado")

        scanner = SSRFScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/import", "target")
        self.assertTrue(any(f['severity'] == 'alta' for f in findings))
        self.assertTrue(any('Internal Service Reachable' in f['technique'] for f in findings))

    def test_file_scheme_local_disclosure(self):
        # SSRF por esquema file:// con lectura de /etc/passwd
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if val.startswith("file:///etc/passwd"):
                return MockResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            return MockResponse("Vista normal")

        scanner = SSRFScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/view", "file")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertIn("Local File Disclosure", findings[0]['technique'])


class TestSSTIScanner(unittest.TestCase):
    def test_jinja2_evaluation_detected(self):
        # Motor tipo Jinja2: evalua aritmetica y concatena cadenas
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", val)
            if m:
                return MockResponse(f"<p>Resultado: {int(m.group(1)) * int(m.group(2))}</p>")
            m = re.fullmatch(r"\{\{(\d+)\*'(\d+)'\}\}", val)
            if m:
                return MockResponse(f"<p>Resultado: {m.group(2) * int(m.group(1))}</p>")
            return MockResponse("<p>Sin resultado</p>")

        scanner = SSTIScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/search", "q")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['cwe'], 'CWE-1336')
        self.assertIn("Jinja2", findings[0]['technique'])

    def test_freemarker_evaluation_detected(self):
        # Motor que evalua la sintaxis ${...}
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            m = re.fullmatch(r"\$\{(\d+)\*(\d+)\}", val)
            if m:
                return MockResponse(f"<p>{int(m.group(1)) * int(m.group(2))}</p>")
            return MockResponse("<p>nada</p>")

        scanner = SSTIScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/render", "name")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertIn("Freemarker", findings[0]['technique'])

    def test_reflected_payload_is_not_evaluation(self):
        # El endpoint refleja la entrada sin evaluarla: no debe alertar
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            return MockResponse(f"<div>Has enviado: {val}</div>")

        scanner = SSTIScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/echo", "q")
        self.assertEqual(len(findings), 0)

    def test_all_payloads_build_correctly(self):
        # Ninguna plantilla debe romper la sustitucion de operandos
        from ghosts_lighter.scanners.ssti import SSTI_PAYLOADS
        scanner = SSTIScanner(MockSession(lambda url, params: MockResponse("")))
        for plantilla, _motor in SSTI_PAYLOADS:
            payload = scanner._construir_payload(plantilla, 123, 456)
            self.assertIn("123", payload)
            self.assertIn("456", payload)
            self.assertNotIn("A", payload)
            self.assertNotIn("B", payload)


class TestCommandInjectionScanner(unittest.TestCase):
    def test_output_based_detection(self):
        # Endpoint que ejecuta el comando y refleja su salida
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            if re.search(r"[;|&`]\s*id\b", val):
                return MockResponse("<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>")
            if re.search(r"[;|&`]\s*cat\s+/etc/passwd", val):
                return MockResponse("<pre>root:x:0:0:root:/root:/bin/bash</pre>")
            return MockResponse(f"<p>Sin resultado para {val}</p>")

        scanner = CommandInjectionScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/ping", "host")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['technique'], 'Output-Based')
        self.assertEqual(findings[0]['cwe'], 'CWE-78')

    def test_reflected_payload_is_not_injection(self):
        # El endpoint devuelve la entrada sin ejecutarla: no debe alertar
        def handler(url, params):
            val = list(params.values())[0] if params else ""
            return MockResponse(f"<div>Comando recibido: {val}</div>")

        scanner = CommandInjectionScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/run", "cmd")
        self.assertEqual(len(findings), 0)

    def test_time_based_blind_detection(self):
        original = cmdi.TIME_PAYLOADS
        cmdi.TIME_PAYLOADS = ['; sleep 1']
        try:
            def handler(url, params):
                val = list(params.values())[0] if params else ""
                if 'sleep' in val:
                    time.sleep(1.0)
                return MockResponse("<p>ok</p>")

            scanner = CommandInjectionScanner(MockSession(handler))
            findings = scanner.scan_endpoint("http://example.local/dns", "host")
            self.assertGreater(len(findings), 0)
            self.assertEqual(findings[0]['technique'], 'Time-Based Blind')
            self.assertEqual(findings[0]['severity'], 'critica')
        finally:
            cmdi.TIME_PAYLOADS = original

    def test_catalog_comes_from_config(self):
        # El catálogo no debe duplicarse: se reutiliza el de config
        from ghosts_lighter.config import WORDLISTS
        catalogo = WORDLISTS['security_payloads']['command_injection']
        self.assertEqual(sorted(cmdi.OUTPUT_PAYLOADS + cmdi.TIME_PAYLOADS), sorted(catalogo))
        self.assertGreater(len(cmdi.TIME_PAYLOADS), 0)
        self.assertGreater(len(cmdi.OUTPUT_PAYLOADS), 0)


class TestGraphQLIntrospectionScanner(unittest.TestCase):
    SCHEMA_JSON = json.dumps({
        "data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "fields": [{"name": "users"}]},
                {"name": "User", "fields": [{"name": "passwordHash"}, {"name": "email"}]},
                {"name": "Session", "fields": [{"name": "accessToken"}]},
            ],
        }}
    })

    def _handler_introspection_on(self, url, params):
        query = (params or {}).get('query', '')
        if '__typename' in query:
            return MockResponse(json.dumps({"data": {"__typename": "Query"}}))
        if '__schema' in query:
            return MockResponse(TestGraphQLIntrospectionScanner.SCHEMA_JSON)
        return MockResponse("{}")

    def test_introspection_enabled_detected(self):
        scanner = GraphQLIntrospectionScanner(MockSession(self._handler_introspection_on))
        findings = scanner.scan_endpoint("http://example.local/graphql")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'media')
        self.assertEqual(findings[0]['technique'], 'Introspection Enabled')
        self.assertEqual(findings[0]['cwe'], 'CWE-200')
        self.assertIn('passwordHash', findings[0]['detalle'])
        self.assertEqual(scanner.endpoints_graphql, ["http://example.local/graphql"])

    def test_introspection_disabled_not_reported(self):
        def handler(url, params):
            query = (params or {}).get('query', '')
            if '__typename' in query:
                return MockResponse(json.dumps({"data": {"__typename": "Query"}}))
            return MockResponse(json.dumps({"errors": [{"message": "GraphQL introspection is not allowed"}]}))

        scanner = GraphQLIntrospectionScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/graphql")
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(scanner.endpoints_graphql), 1)

    def test_non_graphql_endpoint_ignored(self):
        def handler(url, params):
            return MockResponse("<html><body>404 Not Found</body></html>", 404)

        scanner = GraphQLIntrospectionScanner(MockSession(handler))
        findings = scanner.scan_endpoint("http://example.local/query")
        self.assertEqual(len(findings), 0)
        self.assertEqual(scanner.endpoints_graphql, [])

    def test_get_fallback_when_post_rejected(self):
        # Algunos servidores GraphQL solo aceptan GET con ?query=
        class PostRechazado(MockSession):
            def post(self, url, json=None, timeout=None, **kwargs):
                return MockResponse("Method Not Allowed", 405)

        scanner = GraphQLIntrospectionScanner(PostRechazado(self._handler_introspection_on))
        findings = scanner.scan_endpoint("http://example.local/graphql")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['technique'], 'Introspection Enabled')


class TestForbiddenBypassScanner(unittest.TestCase):
    def test_header_bypass_detected(self):
        def handler(method, url, headers):
            if method == 'GET' and headers.get('X-Forwarded-For') == '127.0.0.1':
                return MockResponse("<html><body>Panel de administracion</body></html>", 200)
            return MockResponse("<html><body>403 Forbidden</body></html>", 403)

        scanner = AccessControl403Scanner(MockBypassSession(handler))
        findings = scanner.scan_endpoint("http://example.local/admin")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertIn('Header Override', findings[0]['technique'])
        self.assertEqual(findings[0]['cwe'], 'CWE-284')

    def test_verb_tampering_detected(self):
        def handler(method, url, headers):
            if method == 'POST':
                return MockResponse("<html><body>Admin API</body></html>", 200)
            return MockResponse("<html><body>403 Forbidden</body></html>", 403)

        scanner = AccessControl403Scanner(MockBypassSession(handler))
        findings = scanner.scan_endpoint("http://example.local/admin")
        self.assertGreater(len(findings), 0)
        self.assertIn('Verb Tampering', findings[0]['technique'])
        self.assertIn('POST', findings[0]['technique'])

    def test_path_manipulation_detected(self):
        def handler(method, url, headers):
            if url.endswith('/admin/'):
                return MockResponse("<html><body>Admin panel</body></html>", 200)
            return MockResponse("<html><body>403 Forbidden</body></html>", 403)

        scanner = AccessControl403Scanner(MockBypassSession(handler))
        findings = scanner.scan_endpoint("http://example.local/admin")
        self.assertGreater(len(findings), 0)
        self.assertIn('Path Manipulation', findings[0]['technique'])

    def test_no_bypass_reported(self):
        def handler(method, url, headers):
            return MockResponse("<html><body>403 Forbidden</body></html>", 403)

        scanner = AccessControl403Scanner(MockBypassSession(handler))
        findings = scanner.scan_endpoint("http://example.local/admin")
        self.assertEqual(len(findings), 0)

    def test_non_protected_path_ignored(self):
        def handler(method, url, headers):
            return MockResponse("<html><body>Home</body></html>", 200)

        scanner = AccessControl403Scanner(MockBypassSession(handler))
        findings = scanner.scan_endpoint("http://example.local/")
        self.assertEqual(len(findings), 0)

    def test_soft_404_not_treated_as_bypass(self):
        # El 200 es un catch-all: el callback del orquestador debe descartarlo
        def handler(method, url, headers):
            if headers:
                return MockResponse("<html><body>Pagina no encontrada</body></html>", 200)
            return MockResponse("<html><body>403 Forbidden</body></html>", 403)

        scanner = AccessControl403Scanner(MockBypassSession(handler), es_respuesta_real=lambda resp: False)
        findings = scanner.scan_endpoint("http://example.local/admin")
        self.assertEqual(len(findings), 0)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b'=').decode()


def _jwt(payload, secret='secret', alg='HS256'):
    """Construye un JWT de prueba sin depender del codigo del scanner."""
    header = _b64({"alg": alg, "typ": "JWT"})
    body = _b64(payload)
    if alg == 'none':
        return f"{header}.{body}."
    firma = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{base64.urlsafe_b64encode(firma).rstrip(b'=').decode()}"


class MockJWTSession:
    """Sesion que entrega al handler el valor del token recibido (cookie o Bearer)."""
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, params=None, timeout=None, **kwargs):
        token = None
        cookies = kwargs.get('cookies') or {}
        if cookies:
            token = list(cookies.values())[0]
        for valor in (kwargs.get('headers') or {}).values():
            if valor.lower().startswith('bearer '):
                token = valor.split(' ', 1)[1]
        return self.handler(url, token)


class TestJWTScanner(unittest.TestCase):
    def test_jwt_shape_detection(self):
        real = _jwt({'sub': '1'})
        self.assertTrue(es_jwt(real))
        self.assertFalse(es_jwt('no-soy-un-jwt'))
        self.assertFalse(es_jwt(''))
        self.assertEqual(extraer_jwts('{"token":"%s"}' % real), [real])

    def test_unsigned_token_detected(self):
        scanner = JWTScanner()
        findings = scanner.analyze(_jwt({'sub': 'admin'}, alg='none'), 'cookie jwt')
        nombres = [f['test'] for f in findings]
        self.assertIn('JWT Sin Firma (alg none)', nombres)
        self.assertEqual(findings[0]['cwe'], 'CWE-347')

    def test_weak_hmac_secret_detected(self):
        scanner = JWTScanner()
        findings = scanner.analyze(_jwt({'sub': '1'}, secret='secret'), 'cookie jwt')
        debiles = [f for f in findings if f['test'] == 'JWT Secreto HMAC Debil']
        self.assertEqual(len(debiles), 1)
        self.assertEqual(debiles[0]['severity'], 'critica')
        self.assertIn('secret', debiles[0]['detalle'])

    def test_strong_hmac_secret_not_cracked(self):
        scanner = JWTScanner()
        fuerte = 'Xk9mQ2pLz7Wn4Rt8Yv3Bc6Df1Gh5Jk0' * 2
        findings = scanner.analyze(_jwt({'sub': '1'}, secret=fuerte), 'cookie jwt')
        self.assertEqual([f for f in findings if f['test'] == 'JWT Secreto HMAC Debil'], [])

    def test_sensitive_claims_and_missing_expiration(self):
        scanner = JWTScanner()
        findings = scanner.analyze(_jwt({'role': 'admin', 'password': 'hunter2'}, secret='Xk9mQ2pLz7Wn4Rt8Yv3Bc6Df1Gh5Jk0'), 'cookie jwt')
        nombres = [f['test'] for f in findings]
        self.assertIn('JWT Claims Sensibles', nombres)
        self.assertIn('JWT Sin Expiracion', nombres)

    def test_alg_none_accepted_detected(self):
        real = _jwt({'sub': 'admin'})
        firma_real = real.split('.')[2]

        def handler(url, token):
            partes = (token or '').split('.')
            if len(partes) != 3:
                return MockResponse('401', 401)
            if partes[2] == '' or partes[2] == firma_real:
                return MockResponse("<html><body>Dashboard de admin</body></html>", 200)
            return MockResponse('401', 401)

        scanner = JWTScanner(MockJWTSession(handler))
        findings = scanner.test_alg_none_aceptado('http://example.local/admin', real, 'cookie', 'jwt')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['test'], 'JWT Sin Firma (alg none)')
        self.assertEqual(findings[0]['technique'], 'alg=none Accepted')

    def test_signature_not_validated_detected(self):
        real = _jwt({'sub': 'admin'})

        def handler(url, token):
            return MockResponse("<html><body>Dashboard de admin</body></html>", 200)

        scanner = JWTScanner(MockJWTSession(handler))
        findings = scanner.test_alg_none_aceptado('http://example.local/admin', real, 'cookie', 'jwt')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['test'], 'JWT Firma No Validada')


class TestIDORScanner(unittest.TestCase):
    def test_horizontal_idor_detected(self):
        # Sesión A (Usuario A) accede a su recurso /api/users/1
        # Sesión B (Usuario B autenticado) accede a /api/users/1 y obtiene los mismos datos privados
        def handler_a(url, params=None, headers=None):
            return MockResponse('{"id": 1, "username": "alice", "email": "alice@corp.local", "role": "user"}', 200)

        def handler_b(url, params=None, headers=None):
            return MockResponse('{"id": 1, "username": "alice", "email": "alice@corp.local", "role": "user"}', 200)

        class MockSessionAB:
            def __init__(self, handler):
                self.handler = handler

            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return self.handler(url, params, headers)

        scanner = IDORScanner(
            session_a=MockSessionAB(handler_a),
            session_b=MockSessionAB(handler_b),
            session_b_authenticated=True
        )
        findings = scanner.scan_endpoint("http://example.local/api/users/1")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['cwe'], 'CWE-639')
        self.assertIn('Horizontal', findings[0]['technique'])

    def test_unauthenticated_vertical_idor_detected(self):
        # Sesión A accede a /profile?id=42
        # Sesión B (anónima) accede a /profile?id=42 y obtiene el panel sin autenticación
        html_content = "<html><body><h1>Perfil de Alice</h1><p>Direccion: 123 Calle Segura</p><p>Saldo: $5,000</p></body></html>"

        class MockSessionAnon:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse(html_content, 200)

        scanner = IDORScanner(
            session_a=MockSessionAnon(),
            session_b=MockSessionAnon(),
            session_b_authenticated=False
        )
        findings = scanner.scan_endpoint("http://example.local/profile?id=42", param="id")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        self.assertEqual(findings[0]['cwe'], 'CWE-639')
        self.assertIn('Unauthenticated', findings[0]['technique'])

    def test_secure_endpoint_rejected_403(self):
        # Sesión A accede correctamente (200), pero Sesión B recibe 403 Forbidden
        class MockSessionA:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse('{"id": 100, "order": "Factura 100"}', 200)

        class MockSessionB:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse('{"error": "Forbidden"}', 403)

        scanner = IDORScanner(
            session_a=MockSessionA(),
            session_b=MockSessionB(),
            session_b_authenticated=True
        )
        findings = scanner.scan_endpoint("http://example.local/api/orders/100")
        self.assertEqual(len(findings), 0)

    def test_login_redirect_safe(self):
        # Sesión B es redirigida a login o recibe formulario de login
        class MockSessionA:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse('{"id": 1, "profile": "data"}', 200)

        class MockSessionB:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse(
                    "<html><body><form action='/login'><input type='password' name='pwd'></form></body></html>",
                    200,
                    headers={'Location': '/login'}
                )

        scanner = IDORScanner(
            session_a=MockSessionA(),
            session_b=MockSessionB(),
            session_b_authenticated=False
        )
        findings = scanner.scan_endpoint("http://example.local/profile?id=1", param="id")
        self.assertEqual(len(findings), 0)

    def test_soft_404_ignored(self):
        # Sesión B devuelve 200 con catch-all; es_respuesta_real lo descarta
        class MockSession:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse("<html><body>Pagina no encontrada</body></html>", 200)

        scanner = IDORScanner(
            session_a=MockSession(),
            session_b=MockSession(),
            es_respuesta_real=lambda resp: False
        )
        findings = scanner.scan_endpoint("http://example.local/api/users/1")
        self.assertEqual(len(findings), 0)

    def test_param_tampering_idor_detected(self):
        # Tampering de parámetro: ?id=1 muta a ?id=2
        class MockSessionTamper:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                if 'id=2' in url:
                    return MockResponse('{"id": 2, "user": "bob", "secret": "bob_data"}', 200)
                return MockResponse('{"id": 1, "user": "alice", "secret": "alice_data"}', 200)

        scanner = IDORScanner(
            session_a=MockSessionTamper(),
            session_b=MockSessionTamper(),
            session_b_authenticated=True
        )
        findings = scanner.scan_endpoint("http://example.local/account?id=1", param="id")
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]['severity'], 'critica')
        tecnicas = [f['technique'] for f in findings]
        self.assertTrue(any('Tampering' in t for t in tecnicas))

    def test_rest_path_tampering_idor_detected(self):
        # Tampering en ruta RESTful: /api/orders/1 -> /api/orders/2
        class MockSessionRest:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                if '/api/orders/2' in url:
                    return MockResponse('{"id": 2, "item": "Servidor", "price": 1000}', 200)
                return MockResponse('{"id": 1, "item": "Laptop", "price": 500}', 200)

        scanner = IDORScanner(
            session_a=MockSessionRest(),
            session_b=MockSessionRest(),
            session_b_authenticated=True
        )
        findings = scanner.scan_endpoint("http://example.local/api/orders/1")
        self.assertGreater(len(findings), 0)
        tecnicas = [f['technique'] for f in findings]
        self.assertTrue(any('Tampering' in t or 'REST' in t for t in tecnicas))

    def test_default_session_b_initialization(self):
        # Si session_b es None, IDORScanner crea una sesión anónima automáticamente
        class MockSessionA:
            def get(self, url, params=None, headers=None, timeout=None, allow_redirects=False):
                return MockResponse('{"id": 1, "data": "secret"}', 200)

        scanner = IDORScanner(session_a=MockSessionA())
        self.assertFalse(scanner.session_b_authenticated)
        self.assertIsNotNone(scanner.session_b)


if __name__ == '__main__':
    unittest.main()
