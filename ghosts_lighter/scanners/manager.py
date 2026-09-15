# -*- coding: utf-8 -*-
"""
Orquestador de auditoría de seguridad web (DAST) - OWASP Top 10.
"""

import sys
import os
import re
import html
import time
import hashlib
import random
import concurrent.futures
import datetime as dt
from urllib.parse import urlparse, urljoin, urlunparse

import requests
from requests.exceptions import SSLError, ConnectionError, Timeout, RequestException

from ghosts_lighter.config import (
    DEFAULT_TIMEOUT,
    ASSET_TIMEOUT,
    PRODUCT_VERSION,
    ANSI_VERDE,
    ANSI_ROJO,
    ANSI_AMARILLO,
    ANSI_BLANCO,
    ANSI_GRIS,
    ANSI_CYAN,
    ANSI_MAGENTA,
    ANSI_RESET,
    ICON_PASS,
    ICON_FAIL,
    ICON_WARN,
    ICON_SKIP,
    ICON_INFO,
    ICON_MASTER,
    ICON_DETECT,
    ICON_API,
    ICON_AUTH,
    ICON_DEP,
    ICON_CRAWL,
    WORDLISTS,
    STATUS_META,
    STATUS_META_DEFAULT,
    TEST_METADATA,
    DEFAULT_METADATA,
    barra_progreso,
    WORDLISTS_DIR
)
from ghosts_lighter.core.models import ResultObject
from ghosts_lighter.crawler.spider import Crawler, BROWSER_AVAILABLE
from ghosts_lighter.auth.detector import LoginDiscoveryEngine
from ghosts_lighter.auth.session_auth import AuthSession
from ghosts_lighter.reporters.engine import ReporterEngine, _get_report_dir
from ghosts_lighter.scanners.sqli import SQLiScanner
from ghosts_lighter.scanners.xss import XSSScanner
from ghosts_lighter.scanners.traversal import TraversalScanner, LFI_PARAM_HINTS
from ghosts_lighter.scanners.ssrf import SSRFScanner, SSRF_PARAM_HINTS, SSRF_PARAM_PRIORITY
from ghosts_lighter.scanners.ssti import SSTIScanner, SSTI_PARAM_HINTS
from ghosts_lighter.scanners.cmdi import CommandInjectionScanner, CMDI_PARAM_HINTS
from ghosts_lighter.scanners.graphql import GraphQLIntrospectionScanner, GRAPHQL_PATHS
from ghosts_lighter.scanners.bypass403 import AccessControl403Scanner, SENSITIVE_PROTECTED_PATHS
from ghosts_lighter.scanners.jwt import JWTScanner, es_jwt, extraer_jwts
from ghosts_lighter.scanners.idor import (
    IDORScanner,
    IDOR_PARAM_HINTS,
    COMMON_OBJECT_PATHS,
    REST_ID_PATTERNS
)

class AuditoriaMejorada:
    STATIC_EXTENSIONS = ('.css', '.js', '.mjs', '.map', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.pdf')

    def __init__(self, target_url, http_port=None, username=None, password=None, login_path=None, max_pages=40, max_depth=2, no_selenium=False, wordlist_path=None, username2=None, password2=None, session_b=None):
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"URL invalida: '{target_url}'")
        if not parsed.hostname:
            raise ValueError("No se pudo determinar el host")
        self.hostname = parsed.hostname
        self.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.http_url = f"http://{self.hostname}:{http_port}" if http_port else f"http://{self.hostname}:80"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': random.choice(WORDLISTS['user_agents'])})
        self.username = username
        self.password = password
        self.username2 = username2
        self.password2 = password2
        self.session_b = session_b if session_b is not None else requests.Session()
        self.session_b.verify = False
        self.session_b.headers.update({'User-Agent': random.choice(WORDLISTS['user_agents'])})
        self.session_b_authenticated = False
        self.session_b_info = "Sesion B no configurada (Guest)"
        self.login_path = login_path
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.use_selenium = BROWSER_AVAILABLE and not no_selenium
        self.test_results = {}
        self.test_messages = {}
        self.test_statuses = {}
        self.total_tests = 0
        self.passed = 0
        self.warns = 0
        self.failed = 0
        self.skipped = 0
        self.crawl_data = {
            'visited': [],
            'forms': [],
            'query_params': {},
            'js_endpoints': [],
            'js_secrets': [],
            'js_bundles_analizados': 0
        }
        self.spa_routes = []
        self.api_endpoints = {}
        self.tech_stack = {}
        self.path_results = []
        self.wordlist_path = wordlist_path
        self.auth_status = (False, 'No se intento autenticacion')
        self.soft_404_activo = False
        self.soft_404_status = None
        self.soft_404_len = None
        self.soft_404_hash = None
        self.result = ResultObject()
        self.result.target_url = self.target_url
        self.findings = []

    def print_result(self, test_name, status, message=""):
        msg = str(message)
        meta = STATUS_META.get(status, STATUS_META_DEFAULT)
        if status == 'WARN':
            self.warns += 1
        elif status == 'SKIP':
            self.skipped += 1
        elif status == 'PASS':
            self.passed += 1
        else:
            self.failed += 1
        self.total_tests += 1
        self.result.add_result(test_name, status, msg)
        self.test_statuses[test_name] = status
        self.test_results[test_name] = status
        self.test_messages[test_name] = msg
        nombre = f"{test_name:<32}"
        print(f"{meta['icon']}{ANSI_BLANCO}{nombre}{meta['ansi']} [{status}] {msg}{ANSI_RESET}")
        return status

    def add_finding(self, test_name, detalle="", url=""):
        meta = TEST_METADATA.get(test_name, DEFAULT_METADATA)
        severity = meta.get('severidad', 'info')
        self.result.add_finding(test_name, severity, detalle, url)
        self.findings.append({
            'test': test_name,
            'severidad': severity,
            'detalle': detalle,
            'url': url
        })

    def _calibrar_soft_404(self):
        canario = f"/gl-canary-{random.randint(100000, 999999)}-noexiste"
        self.soft_404_activo = False
        self.soft_404_status = None
        self.soft_404_len = None
        self.soft_404_hash = None
        try:
            resp = self.session.get(f"{self.target_url}{canario}", timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            self.soft_404_status = resp.status_code
            self.soft_404_len = len(resp.text)
            self.soft_404_hash = hashlib.sha256(resp.text.encode('utf-8', errors='ignore')).hexdigest()
            if resp.status_code == 200:
                self.soft_404_activo = True
                self.print_result("Calibracion Soft-404", "WARN", "Server responds with 200 to non-existent paths (SPA fallback) - Path Scan and API Discovery will filter by content")
                return
            self.print_result("Calibracion Soft-404", "PASS", f"Server responds with {resp.status_code} to non-existent paths (expected behavior)")
        except Exception as e:
            self.print_result("Calibracion Soft-404", "SKIP", f"Could not calibrate: {e}")

    def _es_respuesta_real(self, response):
        if not self.soft_404_activo:
            return response.status_code == 200
        if response.status_code != 200:
            return False
        cuerpo = response.text
        if len(cuerpo) == self.soft_404_len:
            digest = hashlib.sha256(cuerpo.encode('utf-8', errors='ignore')).hexdigest()
            if digest == self.soft_404_hash:
                return False
        if self.soft_404_len:
            if abs(len(cuerpo) - self.soft_404_len) / max(self.soft_404_len, 1) < 0.05:
                return False
        return True

    def _es_asset_estatico(self, url):
        parsed = urlparse(url)
        return any(parsed.path.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _strip_query(self, url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

    def _candidatos_ssrf(self):
        """Candidatos (url, parametro) priorizando solo nombres que controlan una peticion server-side."""
        candidatos = []
        vistos = set()

        def agregar(url, param):
            clave = (self._strip_query(url), param.lower())
            if clave in vistos:
                return
            vistos.add(clave)
            candidatos.append((url, param))

        urls = [u for u in (self.crawl_data.get('visited') or [self.target_url]) if not self._es_asset_estatico(u)]
        query_params = self.crawl_data.get('query_params', {})

        # 1. Parametros reales descubiertos en querystrings (maxima prioridad)
        for url in urls[:15]:
            for param in sorted(query_params.get(self._strip_query(url), set())):
                if param.lower() in SSRF_PARAM_HINTS:
                    agregar(url, param)

        # 2. Nombres de parametro tipicos de SSRF sobre las URLs descubiertas
        for url in urls[:8]:
            for param in SSRF_PARAM_PRIORITY[:6]:
                agregar(url, param)

        return candidatos

    def _target_urls_para_inyeccion(self):
        candidatos = []
        for url in (self.crawl_data['visited'] or [self.target_url]):
            if self._es_asset_estatico(url):
                continue
            params = set(WORDLISTS['test_parameters'][:8])
            params |= self.crawl_data['query_params'].get(self._strip_query(url), set())
            candidatos.append((url, params))

        for endpoint in self.crawl_data.get('js_endpoints', []):
            if self._es_asset_estatico(endpoint):
                continue
            url = urljoin(self.target_url + '/', endpoint.lstrip('/'))
            candidatos.append((url, set(WORDLISTS['test_parameters'][:6])))

        for path in WORDLISTS.get('common_vuln_paths', []):
            url = urljoin(self.target_url + '/', path.lstrip('/'))
            if self._es_asset_estatico(url):
                continue
            candidatos.append((url, set(WORDLISTS['test_parameters'][:6])))

        return candidatos[:35]

    def _candidatos_graphql(self):
        """Candidatos a endpoint GraphQL: rutas comunes + endpoints vistos en crawler y JS."""
        candidatos = []
        vistos = set()

        def agregar(url):
            norm = self._strip_query(url).rstrip('/').lower()
            if not norm or norm in vistos:
                return
            vistos.add(norm)
            candidatos.append(url)

        for path in GRAPHQL_PATHS:
            agregar(urljoin(self.target_url + '/', path.lstrip('/')))

        patron_graphql = re.compile(r'graphql|/gql\b|/graphiql', re.I)
        for endpoint in self.crawl_data.get('js_endpoints', []):
            if patron_graphql.search(endpoint):
                agregar(urljoin(self.target_url + '/', endpoint.lstrip('/')))

        for url in self.crawl_data.get('visited', []):
            if patron_graphql.search(url):
                agregar(url)

        return candidatos[:12]

    def _candidatos_token(self):
        """Endpoints que pueden emitir un JWT: los referenciados por la app + rutas comunes."""
        patron = re.compile(r'token|jwt|auth|session|login|oauth', re.I)
        candidatos = []
        vistos = set()

        for endpoint in self.crawl_data.get('js_endpoints', []):
            if not patron.search(endpoint):
                continue
            norm = endpoint.lower()
            if norm in vistos:
                continue
            vistos.add(norm)
            candidatos.append(urljoin(self.target_url + '/', endpoint.lstrip('/')))

        for path in ('/api/token', '/api/auth/token', '/auth/token', '/token', '/api/session', '/jwt'):
            url = urljoin(self.target_url + '/', path.lstrip('/'))
            if url.lower() in vistos:
                continue
            vistos.add(url.lower())
            candidatos.append(url)

        return candidatos[:8]

    def _descubrir_tokens_jwt(self):
        """Recolecta JWT desde las cookies de sesion y desde endpoints de emision."""
        tokens = []
        vistos = set()

        # 1. Cookies de la sesion (incluye las obtenidas tras el login)
        try:
            for cookie in self.session.cookies:
                valor = cookie.value or ''
                if es_jwt(valor) and valor not in vistos:
                    vistos.add(valor)
                    tokens.append({
                        'token': valor,
                        'origen': f"cookie '{cookie.name}'",
                        'transporte': 'cookie',
                        'nombre': cookie.name
                    })
        except Exception:
            pass

        # 2. Endpoints que emiten tokens
        for url in self._candidatos_token():
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
                texto = resp.text or ''
            except Exception:
                continue
            for token in extraer_jwts(texto):
                if token in vistos:
                    continue
                vistos.add(token)
                tokens.append({
                    'token': token,
                    'origen': url,
                    'transporte': 'header',
                    'nombre': 'Authorization'
                })

        return tokens

    def _probe_autenticado(self, cookie_name):
        """Endpoint que responde 200 con el token valido y no deberia con uno invalidado."""
        for url in (self.crawl_data.get('visited') or [])[:6]:
            if self._es_asset_estatico(url):
                continue
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if resp.status_code != 200 or not self._es_respuesta_real(resp):
                    continue
                # Control: con el token invalidado la pagina no debe seguir accesible
                invalido = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False, cookies={cookie_name: 'invalido'})
                if invalido.status_code == 200 and self._es_respuesta_real(invalido):
                    continue
                return url
            except Exception:
                continue
        return None

    def fase_descubrimiento(self):
        print(f"\n{ANSI_MAGENTA}=== DESCUBRIMIENTO (CRAWLER) ==={ANSI_RESET}")
        self._calibrar_soft_404()
        crawler = Crawler(self.session, self.target_url, max_pages=self.max_pages, max_depth=self.max_depth, use_selenium=self.use_selenium)
        try:
            self.crawl_data = crawler.crawl()
            n_urls = len(self.crawl_data['visited'])
            n_forms = len(self.crawl_data['forms'])
            n_params = sum(len(v) for v in self.crawl_data['query_params'].values())
            if n_urls <= 1 and self.use_selenium:
                self.print_result('Descubrimiento (Crawler)', 'WARN', f"Solo {n_urls} URL visitada, {n_forms} formularios, {n_params} parametros de query")
            elif n_urls <= 1:
                self.print_result('Descubrimiento (Crawler)', 'WARN', f"Solo {n_urls} URL (Selenium no disponible - posible SPA sin renderizar)")
            else:
                self.print_result('Descubrimiento (Crawler)', 'PASS', f"{n_urls} URLs, {n_forms} formularios, {n_params} parametros de query")
            self.spa_routes = self.crawl_data['visited']
        except Exception as e:
            self.print_result('Descubrimiento (Crawler)', 'FAIL', f"Error: {e}")

        if self.use_selenium:
            self.print_result('SPA Discovery', 'PASS' if len(self.crawl_data['visited']) > 1 else 'WARN', "Renderizado JS integrado en el crawler")
        else:
            self.print_result('SPA Discovery', 'SKIP', "Playwright no disponible - vea nota de instalacion (pip install playwright && playwright install chromium)")

        n_bundles = self.crawl_data.get('js_bundles_analizados', 0)
        n_omitidos = self.crawl_data.get('js_bundles_omitidos', 0)
        n_js_endpoints = len(self.crawl_data.get('js_endpoints', []))
        n_secrets = len(self.crawl_data.get('js_secrets', []))
        sufijo_omitidos = f" ({n_omitidos} omitidos por limite MAX_JS_BUNDLES)" if n_omitidos > 0 else ""
        if n_bundles == 0:
            self.print_result('JS Static Analysis', 'SKIP', "No se encontraron bundles JS para analizar")
        elif n_secrets > 0:
            for s in self.crawl_data['js_secrets']:
                self.add_finding("Exposicion de Secretos en JS", f"Posible {s['tipo']} hardcodeado: {s['valor_redactado']}", s['fuente'])
            self.print_result('JS Static Analysis', 'FAIL', f"{n_bundles} bundles analizados{sufijo_omitidos} | {n_js_endpoints} endpoints | {n_secrets} posibles secretos hardcodeados")
        else:
            self.print_result('JS Static Analysis', 'PASS', f"{n_bundles} bundles analizados{sufijo_omitidos} | {n_js_endpoints} endpoints de API descubiertos")

        if self.username and self.password:
            auth = AuthSession(self.session, self.target_url, self.username, self.password, self.login_path)
            ok, msg = auth.attempt_login(self.crawl_data['forms'])
            self.auth_status = (ok, msg)
            self.result.auth_status = (ok, msg)
            if ok:
                usuarios_defaults = set(WORDLISTS['default_credentials']['users'])
                passwords_defaults = set(WORDLISTS['default_credentials']['passwords'])
                es_credencial_default = (self.username.lower() in usuarios_defaults and self.password.lower() in passwords_defaults)
                if es_credencial_default:
                    detalle_fail = f"Acceso exitoso utilizando credenciales por defecto detectadas ({self.username}:{self.password})"
                    self.add_finding("Login / Autenticacion", detalle_fail, self.target_url)
                    self.print_result("Login / Autenticacion", "FAIL", f"{msg} - Vulnerabilidad: Credenciales por defecto")
                else:
                    self.print_result("Login / Autenticacion", "PASS", f"{msg} (Credenciales seguras / no estandar)")

                crawler2 = Crawler(self.session, self.target_url, max_pages=self.max_pages, max_depth=self.max_depth, use_selenium=self.use_selenium)
                try:
                    post_login = crawler2.crawl()
                    if len(post_login['visited']) > len(self.crawl_data['visited']):
                        self.crawl_data = post_login
                        self.spa_routes = self.crawl_data['visited']
                        self.result.crawl_data = self.crawl_data
                except Exception:
                    pass
            else:
                forms_found = len(self.crawl_data.get('forms', []))
                login_status, login_msg = LoginDiscoveryEngine.classify_login_result(ok, msg, forms_found)
                self.print_result("Login / Autenticacion", login_status, login_msg)
        else:
            self.print_result("Login / Autenticacion", "SKIP", "Requiere --username y --password")

        # Inicialización de Sesión B (Usuario secundario para IDOR o sesión anónima/invitado)
        if self.username2 and self.password2:
            auth2 = AuthSession(self.session_b, self.target_url, self.username2, self.password2, self.login_path)
            ok2, msg2 = auth2.attempt_login(self.crawl_data['forms'])
            self.session_b_authenticated = ok2
            self.session_b_info = f"Sesion B autenticada ({self.username2})" if ok2 else f"Sesion B fallo auth: {msg2}"
        else:
            self.session_b_authenticated = False
            self.session_b_info = "Sesion B anonima (Guest)"

        self.result.crawl_data = self.crawl_data
        self.result.api_endpoints = self.api_endpoints
        self.result.tech_stack = self.tech_stack

    def test_https_obligatorio(self):
        try:
            response = self.session.get(self.http_url, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get('Location', '')
                if location.lower().startswith('https'):
                    return self.print_result("HTTPS Obligatorio", "PASS", f"Redireccion a HTTPS detectada ({response.status_code})")
                return self.print_result("HTTPS Obligatorio", "FAIL", f"Redirige ({response.status_code}) pero NO hacia HTTPS")
            return self.print_result("HTTPS Obligatorio", "FAIL", f"El puerto HTTP respondio {response.status_code}, sin redirigir")
        except ConnectionError:
            return self.print_result("HTTPS Obligatorio", "FAIL", "Puerto cerrado o firewall del host bloqueando la conexion")
        except Timeout:
            return self.print_result("HTTPS Obligatorio", "FAIL", "Timeout")
        except RequestException as e:
            return self.print_result("HTTPS Obligatorio", "FAIL", f"Error: {e}")

    def test_ssl_certificate(self):
        if urlparse(self.target_url).scheme != 'https':
            return self.print_result("Certificado SSL/TLS", "SKIP", "El objetivo no usa HTTPS")
        try:
            response = requests.get(self.target_url, timeout=DEFAULT_TIMEOUT, verify=True)
            if response.status_code == 200:
                return self.print_result("Certificado SSL/TLS", "PASS", "Certificado valido")
        except SSLError:
            try:
                response = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
                if response.status_code == 200:
                    return self.print_result("Certificado SSL/TLS", "WARN", "Canal cifrado (autofirmado)")
            except Exception:
                pass
        except Exception as e:
            return self.print_result("Certificado SSL/TLS", "FAIL", f"Error: {e}")
        return self.print_result("Certificado SSL/TLS", "FAIL", "No se pudo verificar")

    def test_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            headers = response.headers
            header_keys = [k.lower() for k in headers.keys()]
            critical = {
                'Strict-Transport-Security': 'strict-transport-security' in header_keys,
                'X-Frame-Options': 'x-frame-options' in header_keys,
                'X-Content-Type-Options': 'x-content-type-options' in header_keys
            }
            optional = {
                'Content-Security-Policy': 'content-security-policy' in header_keys,
                'X-XSS-Protection': 'x-xss-protection' in header_keys,
                'Referrer-Policy': 'referrer-policy' in header_keys
            }
            crit_passed = sum(critical.values())
            opt_passed = sum(optional.values())
            total = crit_passed + opt_passed
            details = "Criticos: " + ", ".join(f"{k}:{'ok' if v else 'x'}" for k, v in critical.items())
            criticas_faltantes = [k for k, v in critical.items() if not v]
            if criticas_faltantes:
                detalle_hallazgo = "Ausencia de cabeceras críticas de seguridad: " + ", ".join(criticas_faltantes) + f" ({total}/6 detectadas)"
                self.add_finding("Headers Seguridad", detalle_hallazgo, self.target_url)
                return self.print_result("Headers Seguridad", "FAIL", f"Faltan críticas ({len(criticas_faltantes)}): {total}/6 headers | {details}")
            if total >= 5:
                return self.print_result("Headers Seguridad", "PASS", f"{total}/6 headers | {details}")
            return self.print_result("Headers Seguridad", "WARN", f"Faltan cabeceras opcionales: {total}/6 headers | {details}")
        except Exception as e:
            return self.print_result("Headers Seguridad", "FAIL", f"Error: {e}")

    def test_static_files(self):
        try:
            response = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            assets = re.findall(r"""(?:src|href)=["']([^"']+\.(?:css|js|png|jpg|jpeg|ico|svg))["']""", response.text)
            if not assets:
                return self.print_result("Archivos Estaticos Optimizados", "PASS", "Sin activos externos")
            assets = list(set(assets))[:5]
            ok = 0
            fallidos = []
            for asset in assets:
                try:
                    url = urljoin(self.target_url + '/', asset)
                    res = self.session.get(url, timeout=ASSET_TIMEOUT)
                    if res.status_code == 200:
                        ok += 1
                    else:
                        fallidos.append(asset)
                except Exception:
                    fallidos.append(asset)

            if ok == len(assets):
                return self.print_result("Archivos Estaticos Optimizados", "PASS", f"{ok}/{len(assets)} accesibles")
            if ok > 0:
                return self.print_result("Archivos Estaticos Optimizados", "WARN", f"{ok}/{len(assets)} accesibles | Fallidos: {', '.join(fallidos[:2])}")
            return self.print_result("Archivos Estaticos Optimizados", "FAIL", f"0/{len(assets)} accesibles")
        except Exception as e:
            return self.print_result("Archivos Estaticos Optimizados", "FAIL", f"Error: {e}")

    def test_diseno_responsive(self):
        try:
            response = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            body = response.text
            viewport = bool(re.search(r"""<meta[^>]+name=["']viewport["']""", body, re.I))
            flex = bool(re.search(r'display\s*:\s*(flex|grid)', body, re.I) or re.search(r"""class=["'][^"']*\b(flex|grid)\b""", body, re.I))
            detectados = sum([viewport, flex])
            detalle = ", ".join(k for k, v in {'Viewport': viewport, 'Flex/Grid': flex}.items() if v) or 'ninguno'
            if detectados == 2:
                return self.print_result("Diseno Responsive", "PASS", f"{detectados}/2: {detalle}")
            if detectados == 1:
                return self.print_result("Diseno Responsive", "WARN", f"{detectados}/2: {detalle}")
            return self.print_result("Diseno Responsive", "FAIL", "No se detectaron indicadores")
        except Exception as e:
            return self.print_result("Diseno Responsive", "FAIL", f"Error: {e}")

    def test_performance(self):
        try:
            inicio = time.perf_counter()
            self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            elapsed = time.perf_counter() - inicio
            if elapsed < 1.0:
                return self.print_result("Performance", "PASS", f"Tiempo: {elapsed:.2f}s - Optimo")
            if elapsed < 3.0:
                return self.print_result("Performance", "WARN", f"Tiempo: {elapsed:.2f}s - Aceptable")
            return self.print_result("Performance", "FAIL", f"Tiempo: {elapsed:.2f}s - Lento")
        except Exception as e:
            return self.print_result("Performance", "FAIL", f"Error: {e}")

    def test_xss_reflejado(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            scanner = XSSScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            info_reflejos = []
            probadas = 0

            for base_url, params in candidatos:
                for param in list(params)[:6]:
                    probadas += 1
                    try:
                        hallazgos = scanner.scan_endpoint(base_url, param)
                        for h in hallazgos:
                            if h.get('severity') == 'critica':
                                confirmados.append(f"{param} @ {base_url}")
                                self.add_finding("Inyeccion XSS Reflejado", h['detalle'], base_url)
                            else:
                                info_reflejos.append(f"{param} @ {base_url}")
                                self.add_finding("Inyeccion XSS Reflejado - No Ejecutable", h['detalle'], base_url)
                    except Exception:
                        pass

            if confirmados:
                return self.print_result("Inyeccion XSS Reflejado", "FAIL", f"{len(confirmados)} vulnerables confirmados (ej: {confirmados[0]}) de {probadas} pruebas")
            if info_reflejos:
                return self.print_result("Inyeccion XSS Reflejado", "WARN", f"Reflejo no ejecutable en {len(info_reflejos)} parámetros (ej: {info_reflejos[0]})")
            if probadas == 0:
                return self.print_result("Inyeccion XSS Reflejado", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("Inyeccion XSS Reflejado", "PASS", f"No se detectaron XSS contextuales ({probadas} endpoints probados)")
        except Exception as e:
            return self.print_result("Inyeccion XSS Reflejado", "FAIL", f"Error: {e}")

    def test_sql_injection(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            scanner = SQLiScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            sospechosos = []
            probadas = 0

            for base_url, params in candidatos:
                for param in list(params)[:6]:
                    probadas += 1
                    try:
                        hallazgos = scanner.scan_endpoint(base_url, param)
                        for h in hallazgos:
                            if h.get('severity') == 'critica':
                                confirmados.append(f"{param} ({h.get('technique', 'SQLi')}) @ {base_url}")
                                self.add_finding("Inyeccion SQL (SQLi)", h['detalle'], base_url)
                            else:
                                sospechosos.append(f"{param} ({h.get('technique', 'SQLi')}) @ {base_url}")
                                self.add_finding("Inyeccion SQL (SQLi) - Sospecha", h['detalle'], base_url)
                    except Exception:
                        pass

            if confirmados:
                return self.print_result("Inyeccion SQL (SQLi)", "FAIL", f"{len(confirmados)} confirmados ({confirmados[0]}) de {probadas} pruebas")
            if sospechosos:
                return self.print_result("Inyeccion SQL (SQLi)", "WARN", f"{len(sospechosos)} sospechosos sin confirmar ({sospechosos[0]}) - revisar")
            if probadas == 0:
                return self.print_result("Inyeccion SQL (SQLi)", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("Inyeccion SQL (SQLi)", "PASS", f"No se detectaron SQLi (Error, Boolean y Time-based) en {probadas} pruebas")
        except Exception as e:
            return self.print_result("Inyeccion SQL (SQLi)", "FAIL", f"Error: {e}")

    def test_ssti(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            scanner = SSTIScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            confirmadas_urls = set()
            probadas = 0

            for base_url, params in candidatos:
                if probadas >= 60:
                    break
                if base_url in confirmadas_urls:
                    continue
                params_a_probar = (params & SSTI_PARAM_HINTS) or params
                for param in list(params_a_probar)[:6]:
                    if probadas >= 60:
                        break
                    probadas += 1
                    try:
                        hallazgos = scanner.scan_endpoint(base_url, param)
                    except Exception:
                        continue
                    if not hallazgos:
                        continue
                    # Un parametro vulnerable ya confirma la evaluacion de
                    # plantillas en ese endpoint: no se repite por cada parametro
                    confirmadas_urls.add(base_url)
                    for h in hallazgos:
                        confirmados.append(f"{param} ({h.get('technique', 'SSTI')}) @ {base_url}")
                        self.add_finding("SSTI (Template Injection)", h['detalle'], base_url)
                    break

            if confirmados:
                return self.print_result("SSTI (Template Injection)", "FAIL", f"{len(confirmados)} confirmados (ej: {confirmados[0]}) de {probadas} parametros probados")
            if probadas == 0:
                return self.print_result("SSTI (Template Injection)", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("SSTI (Template Injection)", "PASS", f"No se detecto evaluacion de plantillas en {probadas} parametros probados")
        except Exception as e:
            return self.print_result("SSTI (Template Injection)", "FAIL", f"Error: {e}")

    def test_command_injection(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            scanner = CommandInjectionScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            confirmadas_urls = set()
            probadas = 0

            for base_url, params in candidatos:
                if probadas >= 30:
                    break
                if base_url in confirmadas_urls:
                    continue
                params_a_probar = (params & CMDI_PARAM_HINTS) or params
                for param in list(params_a_probar)[:5]:
                    if probadas >= 30:
                        break
                    probadas += 1
                    try:
                        hallazgos = scanner.scan_endpoint(base_url, param)
                    except Exception:
                        continue
                    if not hallazgos:
                        continue
                    # Un parametro confirmado ya valida la inyeccion en ese endpoint
                    confirmadas_urls.add(base_url)
                    for h in hallazgos:
                        confirmados.append(f"{param} ({h.get('technique', 'CMDi')}) @ {base_url}")
                        self.add_finding("OS Command Injection", h['detalle'], base_url)
                    break

            if confirmados:
                return self.print_result("OS Command Injection", "FAIL", f"{len(confirmados)} confirmados (ej: {confirmados[0]}) de {probadas} parametros probados")
            if probadas == 0:
                return self.print_result("OS Command Injection", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("OS Command Injection", "PASS", f"No se detecto inyeccion de comandos (Output y Time-based) en {probadas} parametros probados")
        except Exception as e:
            return self.print_result("OS Command Injection", "FAIL", f"Error: {e}")

    def test_path_traversal(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            scanner = TraversalScanner(self.session, timeout=DEFAULT_TIMEOUT)
            vulnerables = []
            probadas = 0

            for base_url, params in candidatos:
                params_a_probar = (params & LFI_PARAM_HINTS) or (params if params else {'file', 'page'})
                for param in list(params_a_probar)[:8]:
                    probadas += 1
                    try:
                        hallazgos = scanner.scan_endpoint(base_url, param)
                        for h in hallazgos:
                            vulnerables.append(f"{param} ({h.get('technique', 'LFI')}) @ {base_url}")
                            self.add_finding("Directory / Path Traversal", h['detalle'], base_url)
                            break
                    except Exception:
                        pass

            if vulnerables:
                return self.print_result("Directory / Path Traversal", "FAIL", f"{len(vulnerables)} vulnerables confirmados (ej: {vulnerables[0]})")
            if probadas == 0:
                return self.print_result("Directory / Path Traversal", "SKIP", "Sin endpoints/parametros para probar inclusión de archivos")
            return self.print_result("Directory / Path Traversal", "PASS", f"No se detectó LFI ni Traversal en {probadas} parámetros probados")
        except Exception as e:
            return self.print_result("Directory / Path Traversal", "FAIL", f"Error: {e}")

    def test_open_redirect(self):
        try:
            malicious = 'http://malicious-external-site.com'
            params = ['url', 'redirect', 'next', 'goto', 'return']
            urls_a_probar = self.crawl_data['visited'][:5] or [self.target_url]
            vulnerables = []
            for base_url in urls_a_probar:
                for param in params:
                    try:
                        response = self.session.get(base_url, params={param: malicious}, allow_redirects=False, timeout=DEFAULT_TIMEOUT)
                        location = response.headers.get('Location', '')
                        if response.status_code in (301, 302, 303, 307, 308):
                            if malicious in location:
                                vulnerables.append(f"{param} @ {base_url}")
                                self.add_finding("Open Redirect Inseguro", f"Redirige a dominio externo via '{param}'", base_url)
                                break
                    except Exception:
                        pass

            if vulnerables:
                return self.print_result("Open Redirect Inseguro", "FAIL", f"{len(vulnerables)} vulnerables (ej: {vulnerables[0]})")
            return self.print_result("Open Redirect Inseguro", "PASS", "No se detecto")
        except Exception as e:
            return self.print_result("Open Redirect Inseguro", "FAIL", f"Error: {e}")

    def test_ssrf(self):
        try:
            scanner = SSRFScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            sospechosos = []
            probadas = 0

            for base_url, param in self._candidatos_ssrf():
                if probadas >= 40:
                    break
                probadas += 1
                try:
                    hallazgos = scanner.scan_endpoint(base_url, param)
                except Exception:
                    continue
                for h in hallazgos:
                    if h.get('severity') == 'critica':
                        confirmados.append(f"{param} ({h.get('technique', 'SSRF')}) @ {base_url}")
                        self.add_finding("SSRF / Cloud Metadata", h['detalle'], base_url)
                    else:
                        sospechosos.append(f"{param} ({h.get('technique', 'SSRF')}) @ {base_url}")
                        self.add_finding("SSRF - Sospecha", h['detalle'], base_url)

            if confirmados:
                return self.print_result("SSRF / Cloud Metadata", "FAIL", f"{len(confirmados)} confirmados (ej: {confirmados[0]}) de {probadas} parametros probados")
            if sospechosos:
                return self.print_result("SSRF / Cloud Metadata", "WARN", f"{len(sospechosos)} sospechosos sin confirmar (ej: {sospechosos[0]}) - revisar")
            if probadas == 0:
                return self.print_result("SSRF / Cloud Metadata", "SKIP", "Sin parametros candidatos a SSRF descubiertos")
            return self.print_result("SSRF / Cloud Metadata", "PASS", f"No se detecto SSRF ni acceso a metadatos en {probadas} parametros probados")
        except Exception as e:
            return self.print_result("SSRF / Cloud Metadata", "FAIL", f"Error: {e}")

    def test_api_discovery(self):
        try:
            endpoints = []
            for endpoint in WORDLISTS['api_endpoints']:
                try:
                    url = f"{self.target_url}{endpoint}"
                    response = self.session.get(url, timeout=3, allow_redirects=False)
                    if response.status_code in (401, 403, 405):
                        endpoints.append(endpoint)
                    elif response.status_code == 200 and self._es_respuesta_real(response):
                        endpoints.append(endpoint)
                except Exception:
                    pass

            self.api_endpoints = {'rest': endpoints}
            if endpoints:
                return self.print_result("API Discovery", "PASS", f"{len(endpoints)} endpoints REST descubiertos")
            return self.print_result("API Discovery", "WARN", "No se detectaron APIs")
        except Exception as e:
            return self.print_result("API Discovery", "FAIL", f"Error: {e}")

    def test_graphql_introspection(self):
        try:
            scanner = GraphQLIntrospectionScanner(self.session, timeout=DEFAULT_TIMEOUT)
            confirmados = []
            probadas = 0

            for url in self._candidatos_graphql():
                probadas += 1
                try:
                    hallazgos = scanner.scan_endpoint(url)
                except Exception:
                    continue
                for h in hallazgos:
                    confirmados.append(url)
                    self.add_finding("GraphQL Introspection", h['detalle'], url)

            graphql_vistos = len(scanner.endpoints_graphql)
            if confirmados:
                return self.print_result("GraphQL Introspection", "FAIL", f"{len(confirmados)} endpoints con introspeccion habilitada (ej: {confirmados[0]})")
            if graphql_vistos:
                return self.print_result("GraphQL Introspection", "PASS", f"{graphql_vistos} endpoints GraphQL detectados, ninguno permite introspeccion")
            return self.print_result("GraphQL Introspection", "SKIP", f"No se detectaron endpoints GraphQL ({probadas} rutas probadas)")
        except Exception as e:
            return self.print_result("GraphQL Introspection", "FAIL", f"Error: {e}")

    def test_tech_detection(self):
        try:
            response = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            headers = response.headers
            server = headers.get('Server', 'Desconocido')
            frameworks = []
            if 'react' in response.text.lower() or '_reactRoot' in response.text:
                frameworks.append('React')
            if 'vue' in response.text.lower() or 'v-app' in response.text:
                frameworks.append('Vue')
            if 'angular' in response.text.lower() or 'ng-app' in response.text:
                frameworks.append('Angular')
            if 'django' in response.text.lower() or 'csrfmiddlewaretoken' in response.text:
                frameworks.append('Django')
            if 'laravel' in response.text.lower() or 'csrf_token' in response.text:
                frameworks.append('Laravel')
            if 'express' in headers.get('X-Powered-By', '').lower():
                frameworks.append('Express')

            self.tech_stack = {'server': server, 'frameworks': frameworks}
            if frameworks:
                return self.print_result("Tech Detection", "PASS", f"Server: {server} | Frameworks: {', '.join(frameworks)}")
            return self.print_result("Tech Detection", "WARN", f"Server: {server}")
        except Exception as e:
            return self.print_result("Tech Detection", "FAIL", f"Error: {e}")

    def test_dependency_scan(self):
        try:
            deps_files = ['/package.json', '/requirements.txt', '/composer.json']
            found = []
            for file in deps_files:
                try:
                    url = f"{self.target_url}{file}"
                    response = self.session.get(url, timeout=3)
                    if response.status_code == 200 and self._es_respuesta_real(response):
                        found.append(file)
                        self.add_finding("Dependency Scan", f"Archivo de dependencias expuesto publicamente: {file}", url)
                except Exception:
                    pass

            if found:
                return self.print_result("Dependency Scan", "WARN", f"Expuestos: {', '.join(found)}")
            return self.print_result("Dependency Scan", "PASS", "No se encontraron archivos de dependencias expuestos")
        except Exception as e:
            return self.print_result("Dependency Scan", "FAIL", f"Error: {e}")

    def _cargar_wordlist(self, wl_path):
        ruta = wl_path
        if not os.path.isabs(ruta):
            candidatos = [
                os.path.join(os.getcwd(), 'wordlists', ruta),
                os.path.join(os.getcwd(), ruta),
                str(WORDLISTS_DIR / ruta),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'wordlists', ruta)
            ]
            for cand in candidatos:
                if os.path.exists(cand):
                    ruta = cand
                    break
        if not os.path.exists(ruta):
            return None, f"no existe '{ruta}'"
        try:
            rutas = []
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    entrada = linea.strip()
                    if not entrada or entrada.startswith('#'):
                        continue
                    if not entrada.startswith('/'):
                        entrada = '/' + entrada.lstrip('/')
                    rutas.append(entrada)
            if not rutas:
                return None, "el archivo esta vacio"
            print(f"{ICON_INFO} Wordlist cargada: {os.path.basename(ruta)} ({len(rutas)} rutas)")
            return rutas, None
        except OSError as e:
            return None, str(e)

    def test_path_scan(self):
        try:
            paths = WORDLISTS['dev_paths']
            if self.wordlist_path:
                externas, error = self._cargar_wordlist(self.wordlist_path)
                if error:
                    return self.print_result("Path Scan", "SKIP", f"Wordlist no cargada ({error}). Usando lista interna.")
                paths = externas
            encontrados_reales = []
            whitelist = WORDLISTS.get('safe_paths_whitelist', [])

            def probar(path):
                try:
                    url = f"{self.target_url}{path}"
                    response = self.session.get(url, timeout=2, allow_redirects=False)
                    if response.status_code in (401, 403):
                        return path
                    if response.status_code == 200 and self._es_respuesta_real(response):
                        return path
                except Exception:
                    return None
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for idx, resultado in enumerate(executor.map(probar, paths), 1):
                    if idx % 2000 == 0:
                        print(f"{ICON_CRAWL} Path Scan progreso: {idx}/{len(paths)} probadas, {len(encontrados_reales)} hallazgos")
                    if resultado and resultado not in whitelist:
                        encontrados_reales.append(resultado)
                        self.add_finding("Path Scan", f"Ruta sensible accesible: {resultado}", f"{self.target_url}{resultado}")

            self.path_results = encontrados_reales
            if encontrados_reales:
                status = 'WARN' if len(encontrados_reales) < 5 else 'FAIL'
                ejemplo = ", ".join(encontrados_reales[:3])
                return self.print_result("Path Scan", status, f"{len(encontrados_reales)} encontrados (ej: {ejemplo})")
            return self.print_result("Path Scan", "PASS", "No se encontraron paths expuestos (excluyendo estándares web)")
        except Exception as e:
            return self.print_result("Path Scan", "FAIL", f"Error: {e}")

    def test_forbidden_bypass(self):
        try:
            scanner = AccessControl403Scanner(
                self.session,
                timeout=DEFAULT_TIMEOUT,
                es_respuesta_real=self._es_respuesta_real
            )

            protegidas = []
            for path in SENSITIVE_PROTECTED_PATHS:
                try:
                    url = urljoin(self.target_url + '/', path.lstrip('/'))
                    resp = self.session.get(url, timeout=3, allow_redirects=False)
                    if resp.status_code in (401, 403):
                        protegidas.append(url)
                except Exception:
                    continue
                if len(protegidas) >= 6:
                    break

            if not protegidas:
                return self.print_result("Bypass de 403", "SKIP", f"Ninguna de las {len(SENSITIVE_PROTECTED_PATHS)} rutas sensibles probadas respondio 401/403")

            confirmados = []
            for url in protegidas:
                try:
                    hallazgos = scanner.scan_endpoint(url)
                except Exception:
                    continue
                for h in hallazgos:
                    confirmados.append(f"{url} -> {h.get('technique', 'bypass')}")
                    self.add_finding("Bypass de 403", h['detalle'], h.get('url', url))

            if confirmados:
                return self.print_result("Bypass de 403", "FAIL", f"{len(confirmados)} bypass confirmados (ej: {confirmados[0]})")
            return self.print_result("Bypass de 403", "PASS", f"{len(protegidas)} rutas protegidas (401/403) sin bypass con cabeceras, verbos ni manipulacion de ruta")
        except Exception as e:
            return self.print_result("Bypass de 403", "FAIL", f"Error: {e}")

    def test_jwt_audit(self):
        try:
            scanner = JWTScanner(self.session, timeout=DEFAULT_TIMEOUT)
            tokens = self._descubrir_tokens_jwt()

            if not tokens:
                return self.print_result("Auditoria JWT", "SKIP", "No se encontro ningun JWT en cookies ni en endpoints de emision")

            confirmados = []
            for item in tokens:
                for h in scanner.analyze(item['token'], item['origen']):
                    nombre = h.get('test', 'Auditoria JWT')
                    confirmados.append(f"{nombre} @ {item['origen']}")
                    self.add_finding(nombre, h['detalle'], item['origen'])

            # Analisis activo: solo con tokens en cookie (transporte controlable)
            en_cookie = next((i for i in tokens if i['transporte'] == 'cookie'), None)
            if en_cookie:
                probe = self._probe_autenticado(en_cookie['nombre'])
                if probe:
                    for h in scanner.test_alg_none_aceptado(probe, en_cookie['token'], 'cookie', en_cookie['nombre']):
                        nombre = h.get('test', 'Auditoria JWT')
                        confirmados.append(f"{nombre} @ {probe}")
                        self.add_finding(nombre, h['detalle'], probe)

            if confirmados:
                return self.print_result("Auditoria JWT", "FAIL", f"{len(confirmados)} debilidades (ej: {confirmados[0]}) en {len(tokens)} tokens analizados")
            return self.print_result("Auditoria JWT", "PASS", f"{len(tokens)} tokens analizados sin firma debil, claims sensibles ni expiracion ausente")
        except Exception as e:
            return self.print_result("Auditoria JWT", "FAIL", f"Error: {e}")

    def _candidatos_idor(self):
        """Identifica endpoints con identificadores de objeto (en query o REST) y rutas sensibles comunes."""
        candidatos = []
        vistos = set()

        def _agregar(url, param=None):
            clave = (url, param)
            if clave not in vistos and not self._es_asset_estatico(url):
                vistos.add(clave)
                candidatos.append((url, param))

        # 1. URLs visitadas con query params o rutas REST
        for u in self.crawl_data.get('visited', []):
            parsed = urlparse(u)
            if parsed.query:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for p, vals in qs.items():
                    p_lower = p.lower()
                    if p_lower in IDOR_PARAM_HINTS or (vals and any(v.isdigit() for v in vals)):
                        _agregar(u, p)
            for pat in REST_ID_PATTERNS:
                if pat.search(parsed.path):
                    _agregar(u, None)

        # 2. Query params descubiertos por el crawler
        for u, params in self.crawl_data.get('query_params', {}).items():
            for p in params:
                if p.lower() in IDOR_PARAM_HINTS:
                    full_u = f"{u}?{p}=1"
                    _agregar(full_u, p)

        # 3. Endpoints descubiertos en bundles JS
        for endpoint in self.crawl_data.get('js_endpoints', []):
            for pat in REST_ID_PATTERNS:
                if pat.search(endpoint):
                    full_u = urljoin(self.target_url, endpoint)
                    _agregar(full_u, None)

        # 4. Fallback: Probar rutas de objetos comunes si se encontraron pocos candidatos
        if len(candidatos) < 5:
            for ruta in COMMON_OBJECT_PATHS:
                full_u = urljoin(self.target_url + '/', ruta.lstrip('/'))
                parsed = urlparse(full_u)
                param = None
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    for k in qs:
                        if k.lower() in IDOR_PARAM_HINTS:
                            param = k
                            break
                _agregar(full_u, param)

        return candidatos[:30]

    def test_idor(self):
        try:
            scanner = IDORScanner(
                session_a=self.session,
                session_b=self.session_b,
                timeout=DEFAULT_TIMEOUT,
                es_respuesta_real=self._es_respuesta_real,
                session_b_authenticated=self.session_b_authenticated
            )
            candidatos = self._candidatos_idor()
            if not candidatos:
                return self.print_result("Auditoria IDOR (Doble Sesion)", "SKIP", "Sin endpoints ni identificadores de objeto para probar")

            confirmados = []
            probadas = 0

            for url, param in candidatos:
                probadas += 1
                try:
                    hallazgos = scanner.scan_endpoint(url, param=param)
                except Exception:
                    continue
                for h in hallazgos:
                    nombre = h.get('test', 'Auditoria IDOR (Doble Sesion)')
                    confirmados.append(f"{h.get('technique', 'IDOR')} @ {h.get('url', url)}")
                    self.add_finding(nombre, h['detalle'], h.get('url', url), cwe=h.get('cwe', 'CWE-639'))

            if confirmados:
                return self.print_result(
                    "Auditoria IDOR (Doble Sesion)", "FAIL",
                    f"{len(confirmados)} vulnerabilidades IDOR confirmadas (ej: {confirmados[0]}) [{self.session_b_info}]"
                )
            return self.print_result(
                "Auditoria IDOR (Doble Sesion)", "PASS",
                f"Control de acceso a nivel de objeto verificado en {probadas} endpoints probados [{self.session_b_info}]"
            )
        except Exception as e:
            return self.print_result("Auditoria IDOR (Doble Sesion)", "FAIL", f"Error: {e}")

    def _reporte_txt(self, output_path=None):
        ahora = dt.datetime.now()
        report_dir = _get_report_dir()
        if output_path is None:
            timestamp = ahora.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(report_dir, f'informe_ghosts_lighter_{timestamp}.txt')
        elif not os.path.isabs(output_path):
            output_path = os.path.join(report_dir, output_path)

        if not output_path.endswith('.txt'):
            output_path = output_path.rsplit('.', 1)[0] + '.txt'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("======================================================================\n")
            f.write("GHOSTS LIGHTER - Reporte de Auditoria de Seguridad\n")
            f.write("======================================================================\n\n")
            f.write(f"Objetivo: {self.target_url}\n")
            f.write(f"Fecha: {ahora.strftime('%d/%m/%Y %H:%M:%S')}\n\n")
            f.write("----------------------------------------------------------------------\nRESULTADOS\n----------------------------------------------------------------------\n\n")
            for nombre, status in self.test_statuses.items():
                f.write(f"[{status}] {nombre}\n    {self.test_messages.get(nombre, '')}\n\n")
            f.write(f"----------------------------------------------------------------------\nReporte generado por GHOSTS LIGHTER v{PRODUCT_VERSION}\nOWASP Top 10:2025\n")

        print(f"   Reporte TXT generado: {output_path}")
        return os.path.abspath(output_path)

    def generar_reporte_html(self, output_path=None):
        total = len(self.test_results)
        passed = sum(1 for v in self.test_statuses.values() if v == 'PASS')
        warns = sum(1 for v in self.test_statuses.values() if v == 'WARN')
        failed = sum(1 for v in self.test_statuses.values() if v == 'FAIL')
        skipped = sum(1 for v in self.test_statuses.values() if v == 'SKIP')
        ejecutadas = total - skipped
        score = ((passed + warns) / ejecutadas * 100) if ejecutadas > 0 else 0.0

        criticos_fail = [n for n in ('Inyeccion SQL (SQLi)', 'Directory / Path Traversal', 'Inyeccion XSS Reflejado', 'Auditoria IDOR (Doble Sesion)') if self.test_statuses.get(n) == 'FAIL']
        if criticos_fail:
            nivel_riesgo, riesgo_css = ('CRITICAL - Active Exploitable Vulnerabilities', 'risk-critical')
        elif failed > 0:
            nivel_riesgo, riesgo_css = ('HIGH - Active Vulnerabilities Detected', 'risk-critical')
        elif warns > 0:
            nivel_riesgo, riesgo_css = ('MODERATE - Hardening Required', 'risk-moderate')
        else:
            nivel_riesgo, riesgo_css = ('EXCELLENT - Secure Posture', 'risk-excellent')

        ahora = dt.datetime.now()
        report_dir = _get_report_dir()
        if output_path is None:
            timestamp = ahora.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(report_dir, f'informe_ghosts_lighter_{timestamp}.html')
        elif not os.path.isabs(output_path):
            output_path = os.path.join(report_dir, output_path)

        if not output_path.endswith('.html'):
            output_path = output_path.rsplit('.', 1)[0] + '.html'

        conteo_status = {}
        for status in self.test_statuses.values():
            conteo_status[status] = conteo_status.get(status, 0) + 1

        resumen_cards = []
        for status, count in sorted(conteo_status.items(), key=lambda kv: STATUS_META.get(kv[0], STATUS_META_DEFAULT)['orden']):
            meta = STATUS_META.get(status, STATUS_META_DEFAULT)
            resumen_cards.append(f"""
            <div class="stat-card stat-{meta['css']}">
                <div class="stat-number">{count}</div>
                <div class="stat-label">{html.escape(status)}</div>
            </div>""")

        group_names = {
            'Auditoria Avanzada': 'Advanced Security Scans',
            'Seguridad OWASP Top 10': 'OWASP Top 10 Vulnerabilities',
            'Arquitectura y Configuracion': 'Architecture & Configuration',
            'Experiencia de Usuario': 'User Experience (UX)',
            'Otras Pruebas': 'General Security Checks'
        }

        test_names = {
            'API Discovery': 'API Endpoint Discovery',
            'Archivos Estaticos Optimizados': 'Static Assets Optimization',
            'Auditoria JWT': 'JWT Security Audit',
            'Auditoria IDOR (Doble Sesion)': 'IDOR / BOLA Dual-Session Audit',
            'Bypass de 403': '403 / 401 Access Control Bypass',
            'Calibracion Soft-404': 'Soft-404 Dynamic Calibration',
            'Certificado SSL/TLS': 'SSL/TLS Certificate Verification',
            'Dependency Scan': 'Dependency & Package Scan',
            'Descubrimiento (Crawler)': 'Web Crawler Discovery',
            'Directory / Path Traversal': 'Directory / Path Traversal (LFI)',
            'Diseno Responsive': 'Responsive Layout Check',
            'Exposicion de Secretos en JS': 'JS Secrets & Credential Exposure',
            'GraphQL Introspection': 'GraphQL Introspection',
            'HTTPS Obligatorio': 'Mandatory HTTPS Enforcement',
            'Headers Seguridad': 'HTTP Security Headers',
            'Inyeccion SQL (SQLi)': 'SQL Injection (SQLi)',
            'Inyeccion SQL (SQLi) - Sospecha': 'SQL Injection (SQLi) - Suspicion',
            'Inyeccion XSS Reflejado': 'Reflected XSS Injection',
            'JS Static Analysis': 'JavaScript Static Analysis',
            'JWT Claims Sensibles': 'JWT Sensitive Claims Exposure',
            'JWT Firma No Validada': 'JWT Signature Verification Failure',
            'JWT Secreto HMAC Debil': 'Weak HMAC Secret (JWT)',
            'JWT Sin Expiracion': 'JWT Missing Expiration (exp)',
            'JWT Sin Firma (alg none)': 'Unsigned JWT Token (alg: none)',
            'Login / Autenticacion': 'Authentication & Login Form Check',
            'OS Command Injection': 'OS Command Injection',
            'Open Redirect Inseguro': 'Insecure Open Redirect',
            'Path Scan': 'Sensitive Path & Directory Scan',
            'Performance': 'Performance Metrics',
            'SPA Discovery': 'SPA Dynamic Discovery',
            'SSRF / Cloud Metadata': 'SSRF & Cloud Metadata',
            'SSRF - Sospecha': 'SSRF - Suspicion',
            'SSTI (Template Injection)': 'Server-Side Template Injection (SSTI)',
            'Tech Detection': 'Technology Stack Fingerprinting'
        }

        grupos = {}
        for nombre, status in self.test_statuses.items():
            meta = TEST_METADATA.get(nombre, DEFAULT_METADATA)
            raw_group = meta.get('grupo', 'Otras Pruebas')
            eng_group = group_names.get(raw_group, raw_group)
            grupos.setdefault(eng_group, []).append((nombre, status))

        secciones_html = []
        for grupo, pruebas in grupos.items():
            filas = []
            for nombre, status in pruebas:
                meta_status = STATUS_META.get(status, STATUS_META_DEFAULT)
                meta_test = TEST_METADATA.get(nombre, DEFAULT_METADATA)
                display_name = test_names.get(nombre, nombre)
                mensaje = html.escape(self.test_messages.get(nombre, ''))
                filas.append(f"""
                <tr>
                    <td class="col-test">{html.escape(display_name)}</td>
                    <td><span class="badge badge-{meta_status['css']}">{html.escape(status)}</span></td>
                    <td class="col-owasp">{html.escape(meta_test.get('owasp', 'General'))}</td>
                    <td class="col-msg">{mensaje}</td>
                </tr>""")
            secciones_html.append(f"""
            <div class="group-section">
                <h3>{html.escape(grupo)}</h3>
                <table>
                    <thead><tr><th>Test Name</th><th>Status</th><th>OWASP Category</th><th>Diagnostic Detail</th></tr></thead>
                    <tbody>{''.join(filas)}</tbody>
                </table>
            </div>""")

        orden_severidad = {'critica': 0, 'critical': 0, 'alta': 1, 'high': 1, 'media': 2, 'medium': 2, 'baja': 3, 'low': 3, 'info': 4}
        findings_ordenados = sorted(self.findings, key=lambda f: orden_severidad.get(f.get('severidad', f.get('severity', 'info')), 5))
        
        sev_labels = {
            'critica': 'CRITICAL',
            'critical': 'CRITICAL',
            'alta': 'HIGH',
            'high': 'HIGH',
            'media': 'MEDIUM',
            'medium': 'MEDIUM',
            'baja': 'LOW',
            'low': 'LOW',
            'info': 'INFO'
        }

        if findings_ordenados:
            filas_f = []
            for f in findings_ordenados:
                raw_sev = f.get('severidad', f.get('severity', 'info'))
                disp_sev = sev_labels.get(raw_sev.lower(), raw_sev.upper())
                raw_test = f.get('test', '')
                disp_test = test_names.get(raw_test, raw_test)
                detalle = f.get('detalle', f.get('description', ''))
                url_val = f.get('url', f.get('endpoint', ''))
                filas_f.append(f"""
                <tr>
                    <td><span class="sev sev-{html.escape(raw_sev.lower())}">{html.escape(disp_sev)}</span></td>
                    <td>{html.escape(disp_test)}</td>
                    <td>{html.escape(detalle)}</td>
                    <td class="col-url">{html.escape(url_val)}</td>
                </tr>""")
            findings_html = f"""
            <div class="group-section">
                <h3>Detailed Findings ({len(findings_ordenados)})</h3>
                <table>
                    <thead><tr><th>Severity</th><th>Vulnerability / Test</th><th>Evidence & Detail</th><th>Affected URL / Endpoint</th></tr></thead>
                    <tbody>{''.join(filas_f)}</tbody>
                </table>
            </div>"""
        else:
            findings_html = '<div class="group-section"><p class="no-findings">No detailed vulnerability findings were identified in this audit run.</p></div>'

        # Directory and attack surface extraction
        n_urls = len(self.crawl_data.get('visited', []))
        n_forms = len(self.crawl_data.get('forms', []))
        n_paths = len(getattr(self, 'path_results', []))
        n_apis = len(self.crawl_data.get('js_endpoints', []))

        urls_lista = ''.join(f"<li>{html.escape(u)}</li>" for u in self.crawl_data.get('visited', [])[:30])
        paths_lista = ''.join(f"<li><span class='path-badge'>PATH</span> {html.escape(p)}</li>" for p in getattr(self, 'path_results', [])[:30])
        apis_lista = ''.join(f"<li><span class='api-badge'>API</span> {html.escape(a)}</li>" for a in self.crawl_data.get('js_endpoints', [])[:30])

        auth_ok, auth_msg = self.auth_status

        paths_subblock = f"""
        <div class="sub-block">
            <h4>Discovered Paths & Directories ({n_paths})</h4>
            {f'<ul class="url-list">{paths_lista}</ul>' if paths_lista else '<p class="no-findings">No exposed sensitive paths or directories detected during path scan.</p>'}
        </div>"""

        apis_subblock = f"""
        <div class="sub-block">
            <h4>Discovered API Endpoints & Routes ({n_apis})</h4>
            {f'<ul class="url-list">{apis_lista}</ul>' if apis_lista else '<p class="no-findings">No external API endpoints identified in JavaScript analysis.</p>'}
        </div>""" if n_apis > 0 else ""

        crawled_subblock = f"""
        <div class="sub-block">
            <h4>Crawled Site URLs ({n_urls})</h4>
            {f'<ul class="url-list">{urls_lista}</ul>' if urls_lista else '<p class="no-findings">No additional URLs crawled.</p>'}
        </div>"""

        descubrimiento_html = f"""
        <div class="group-section">
            <h3>Discovered Attack Surface & Directories</h3>
            <p><b>Visited URLs:</b> {n_urls} &nbsp;|&nbsp; <b>Forms:</b> {n_forms} &nbsp;|&nbsp;
               <b>Discovered Paths / Dirs:</b> {n_paths} &nbsp;|&nbsp;
               <b>Authentication:</b> {'Authenticated' if auth_ok else 'Unauthenticated / Guest'} ({html.escape(auth_msg)})</p>
            {paths_subblock}
            {apis_subblock}
            {crawled_subblock}
        </div>"""

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GHOSTS LIGHTER - Security Audit for {html.escape(self.hostname)}</title>
<style>
  :root {{
    --bg: #0a0405;
    --panel: #140709;
    --panel-hover: #1c0b0e;
    --border: #3a1015;
    --border-glow: #6e1a23;
    --text: #f5e8ea;
    --muted: #a68489;
    --accent: #ff2a44;
    --accent-glow: rgba(255, 42, 68, 0.25);
    --pass: #2ecc71;
    --warn: #f39c12;
    --fail: #ff2a44;
    --skip: #7a828e;
    --info: #ff5266;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }}
  .container {{ max-width: 1120px; margin: 0 auto; padding: 36px 24px 64px; }}
  header {{ text-align: center; margin-bottom: 28px; }}
  header h1 {{
    font-size: 32px;
    margin: 0;
    letter-spacing: 3px;
    color: var(--accent);
    text-shadow: 0 0 25px var(--accent-glow);
    font-weight: 800;
  }}
  header p {{ color: var(--muted); margin: 6px 0 0; font-size: 14px; }}
  .meta-box {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  }}
  .meta-box div {{ margin: 5px 0; font-size: 13.5px; }}
  .meta-box b {{ color: #ff6b7e; }}
  .risk-banner {{
    text-align: center;
    padding: 16px;
    border-radius: 10px;
    font-weight: 700;
    font-size: 15px;
    margin-bottom: 24px;
    letter-spacing: 0.5px;
  }}
  .risk-critical {{
    background: rgba(255, 42, 68, 0.16);
    border: 1px solid var(--fail);
    color: #ff5266;
    box-shadow: 0 0 20px rgba(255, 42, 68, 0.25);
  }}
  .risk-moderate {{
    background: rgba(243, 156, 18, 0.15);
    border: 1px solid var(--warn);
    color: var(--warn);
  }}
  .risk-excellent {{
    background: rgba(46, 204, 113, 0.15);
    border: 1px solid var(--pass);
    color: var(--pass);
  }}
  .stats-grid {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 28px; }}
  .stat-card {{
    flex: 1;
    min-width: 120px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    transition: transform 0.15s ease, border-color 0.15s ease;
  }}
  .stat-card:hover {{ transform: translateY(-2px); border-color: var(--border-glow); }}
  .stat-number {{ font-size: 30px; font-weight: 800; }}
  .stat-label {{ color: var(--muted); font-size: 11px; letter-spacing: 1.5px; margin-top: 4px; font-weight: 600; }}
  .stat-pass .stat-number {{ color: var(--pass); }}
  .stat-warn .stat-number {{ color: var(--warn); }}
  .stat-fail .stat-number {{ color: var(--fail); text-shadow: 0 0 15px rgba(255, 42, 68, 0.4); }}
  .stat-skip .stat-number {{ color: var(--skip); }}
  .stat-info .stat-number {{ color: #ff7686; }}
  .score-box {{ text-align: center; margin-bottom: 32px; }}
  .score-value {{
    font-size: 52px;
    font-weight: 900;
    color: var(--accent);
    text-shadow: 0 0 30px rgba(255, 42, 68, 0.35);
  }}
  .score-label {{ color: var(--muted); font-size: 13px; max-width: 600px; margin: 0 auto; }}
  .group-section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px;
    margin-bottom: 24px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
  }}
  .group-section h3 {{
    margin-top: 0;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    font-size: 18px;
    letter-spacing: 0.5px;
  }}
  .sub-block {{ margin-top: 18px; }}
  .sub-block h4 {{
    margin: 0 0 8px;
    color: #ff6b7e;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: .8px; }}
  tr:hover td {{ background: rgba(255, 42, 68, 0.03); }}
  .col-test {{ font-weight: 600; white-space: nowrap; color: #fce8eb; }}
  .col-owasp {{ color: var(--muted); white-space: nowrap; font-size: 12px; }}
  .col-msg {{ color: #d6b8bd; }}
  .col-url {{ color: var(--muted); word-break: break-all; font-family: monospace; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: .5px; }}
  .badge-pass {{ background: rgba(46, 204, 113, 0.15); color: var(--pass); border: 1px solid rgba(46, 204, 113, 0.3); }}
  .badge-warn {{ background: rgba(243, 156, 18, 0.15); color: var(--warn); border: 1px solid rgba(243, 156, 18, 0.3); }}
  .badge-fail {{ background: rgba(255, 42, 68, 0.18); color: #ff5266; border: 1px solid rgba(255, 42, 68, 0.4); }}
  .badge-skip {{ background: rgba(122, 130, 142, 0.15); color: var(--skip); border: 1px solid rgba(122, 130, 142, 0.3); }}
  .badge-info {{ background: rgba(255, 82, 102, 0.15); color: #ff7686; border: 1px solid rgba(255, 82, 102, 0.3); }}
  .sev {{ display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 800; letter-spacing: 0.5px; }}
  .sev-critica, .sev-critical {{ background: #ff2a44; color: #fff; box-shadow: 0 0 10px rgba(255, 42, 68, 0.4); }}
  .sev-alta, .sev-high {{ background: rgba(255, 42, 68, 0.65); color: #fff; }}
  .sev-media, .sev-medium {{ background: rgba(243, 156, 18, 0.65); color: #fff; }}
  .sev-baja, .sev-low {{ background: rgba(122, 130, 142, 0.5); color: #fff; }}
  .sev-info {{ background: rgba(255, 82, 102, 0.4); color: #fff; }}
  .path-badge {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; background: rgba(255, 42, 68, 0.2); color: #ff6b7e; margin-right: 6px; }}
  .api-badge {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; background: rgba(52, 152, 219, 0.2); color: #5dade2; margin-right: 6px; }}
  .no-findings {{ color: var(--muted); font-size: 13px; font-style: italic; margin: 6px 0; }}
  .url-list {{
    column-count: 2;
    font-family: monospace;
    font-size: 12px;
    color: #e3cad0;
    max-height: 240px;
    overflow-y: auto;
    background: #0f0506;
    padding: 12px 18px;
    border-radius: 6px;
    border: 1px solid var(--border);
    margin: 8px 0;
  }}
  .url-list li {{ margin-bottom: 4px; word-break: break-all; }}
  footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px; letter-spacing: 0.5px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>GHOSTS LIGHTER</h1>
    <p>Web Application Security Assessment Report</p>
  </header>

  <div class="meta-box">
    <div><b>Target:</b> {html.escape(self.target_url)}</div>
    <div><b>Audit Date:</b> {ahora.strftime('%Y-%m-%d %H:%M:%S')}</div>
    <div><b>Engine Version:</b> GHOSTS LIGHTER v{PRODUCT_VERSION}</div>
  </div>

  <div class="risk-banner {riesgo_css}">{html.escape(nivel_riesgo)}</div>

  <div class="stats-grid">{''.join(resumen_cards)}</div>

  <div class="score-box">
    <div class="score-value">{score:.1f}%</div>
    <div class="score-label">Overall test pass rate ({ejecutadas} executed, {skipped} skipped)</div>
  </div>

  {descubrimiento_html}
  {findings_html}
  {''.join(secciones_html)}

  <footer>Report generated by GHOSTS LIGHTER v{PRODUCT_VERSION} &middot; OWASP Top 10 (2025)</footer>
</div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_doc)
        return os.path.abspath(output_path)

    def run_audit(self, generar_html=True, output_path=None):
        print(f"{ICON_INFO} Starting GHOSTS LIGHTER Security Audit v{PRODUCT_VERSION}")
        print(f"   Target: {self.target_url}")
        print("===========================================================================")

        total_fases = 22
        fase_actual = 0

        def avanzar_fase(nombre_etapa=""):
            nonlocal fase_actual
            fase_actual += 1
            barra_progreso(fase_actual, total_fases, longitud=30, prefijo="Audit Progress:")
            if nombre_etapa:
                print(f"\n{ANSI_CYAN}--- [{fase_actual}/{total_fases}] {nombre_etapa} ---{ANSI_RESET}")

        avanzar_fase("Discovery & Web Crawling")
        self.fase_descubrimiento()

        avanzar_fase("Mandatory HTTPS Validation")
        self.test_https_obligatorio()

        avanzar_fase("SSL/TLS Certificate Verification")
        self.test_ssl_certificate()

        avanzar_fase("Security Headers Analysis")
        self.test_security_headers()

        avanzar_fase("Static Files Optimization")
        self.test_static_files()

        avanzar_fase("Reflected XSS Injection Tests")
        self.test_xss_reflejado()

        avanzar_fase("SQL Injection (SQLi) Tests")
        self.test_sql_injection()

        avanzar_fase("Server-Side Template Injection (SSTI) Tests")
        self.test_ssti()

        avanzar_fase("OS Command Injection Tests")
        self.test_command_injection()

        avanzar_fase("Directory / Path Traversal Scan")
        self.test_path_traversal()

        avanzar_fase("Insecure Open Redirect Verification")
        self.test_open_redirect()

        avanzar_fase("SSRF & Cloud Metadata Tests")
        self.test_ssrf()

        avanzar_fase("Responsive Design Assessment")
        self.test_diseno_responsive()

        avanzar_fase("Performance Metrics")
        self.test_performance()

        avanzar_fase("API Discovery")
        self.test_api_discovery()

        avanzar_fase("GraphQL Introspection")
        self.test_graphql_introspection()

        avanzar_fase("Technology Stack Detection")
        self.test_tech_detection()

        avanzar_fase("Exposed Dependencies Scan")
        self.test_dependency_scan()

        avanzar_fase("Sensitive Path Scan")
        self.test_path_scan()

        avanzar_fase("Access Control Bypass (403/401)")
        self.test_forbidden_bypass()

        avanzar_fase("JWT Security Audit")
        self.test_jwt_audit()

        avanzar_fase("IDOR / Access Control Audit (Dual-Session)")
        self.test_idor()

        total = len(self.test_results)
        passed = sum(1 for v in self.test_statuses.values() if v == 'PASS')
        warns = sum(1 for v in self.test_statuses.values() if v == 'WARN')
        failed = sum(1 for v in self.test_statuses.values() if v == 'FAIL')
        skipped = sum(1 for v in self.test_statuses.values() if v == 'SKIP')
        score = ((passed + warns) / (total - skipped) * 100) if (total - skipped) > 0 else 0

        if failed > 0:
            nivel_riesgo = 'CRITICAL - Immediate attention required' if failed > 2 else 'HIGH - Active vulnerabilities detected'
        elif warns > 0:
            nivel_riesgo = 'MODERATE - Hardening recommended'
        else:
            nivel_riesgo = 'LOW - Acceptable security posture'

        print(f"\n{ANSI_CYAN}=== AUDIT SUMMARY ==={ANSI_RESET}")
        print(f"   {ANSI_VERDE}PASS{ANSI_RESET}: {passed} | {ANSI_AMARILLO}WARN{ANSI_RESET}: {warns}")
        print(f"   {ANSI_ROJO}FAIL{ANSI_RESET}: {failed} | {ANSI_GRIS}SKIP{ANSI_RESET}: {skipped}")
        print(f"   Total tests: {total} | Executed: {total - skipped}")
        print(f"   Detailed findings: {len(self.findings)} | Risk Level: {nivel_riesgo}")

        reporte_path = None
        reporte_json = None
        reporte_sarif = None

        if generar_html:
            reporter = ReporterEngine(result=self.result, target_url=self.target_url, hostname=self.hostname)
            reporte_json = reporter.generate_json()
            reporte_sarif = reporter.generate_sarif()
            reporte_path = self.generar_reporte_html(output_path)

            print(f"\n{ANSI_CYAN}=== GENERATED REPORTS ==={ANSI_RESET}")
            print(f"   HTML: {reporte_path}")
            print(f"   JSON: {reporte_json}")
            print(f"   SARIF: {reporte_sarif}")


# English aliases for the main assessment engine class
SecurityAuditEngine = AuditoriaMejorada
EnhancedAudit = AuditoriaMejorada

