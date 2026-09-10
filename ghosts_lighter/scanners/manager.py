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

class AuditoriaMejorada:
    STATIC_EXTENSIONS = ('.css', '.js', '.mjs', '.map', '.json', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.pdf')

    def __init__(self, target_url, http_port=None, username=None, password=None, login_path=None, max_pages=40, max_depth=2, no_selenium=False, wordlist_path=None):
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
                self.print_result("Calibracion Soft-404", "WARN", "El servidor responde 200 a rutas inexistentes (fallback SPA) - Path Scan y API Discovery filtraran por contenido, no solo status code")
                return
            self.print_result("Calibracion Soft-404", "PASS", f"El servidor responde {resp.status_code} a rutas inexistentes (comportamiento esperado)")
        except Exception as e:
            self.print_result("Calibracion Soft-404", "SKIP", f"No se pudo calibrar: {e}")

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
            payloads = WORDLISTS['security_payloads']['xss'][:4]
            vulnerables = []
            probadas = 0
            for base_url, params in candidatos:
                for param in list(params)[:6]:
                    for payload in payloads:
                        probadas += 1
                        try:
                            response = self.session.get(base_url, params={param: payload}, timeout=DEFAULT_TIMEOUT)
                            if payload in response.text:
                                vulnerables.append(f"{param} @ {base_url}")
                                self.add_finding("Inyeccion XSS Reflejado", f"Payload reflejado sin sanitizar en parametro '{param}'", base_url)
                                break
                        except Exception:
                            pass

            if vulnerables:
                return self.print_result("Inyeccion XSS Reflejado", "FAIL", f"{len(vulnerables)} vulnerables (ej: {vulnerables[0]}) de {probadas} pruebas")
            if probadas == 0:
                return self.print_result("Inyeccion XSS Reflejado", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("Inyeccion XSS Reflejado", "PASS", f"No se detectaron XSS ({probadas} pruebas sobre {len(candidatos)} endpoints)")
        except Exception as e:
            return self.print_result("Inyeccion XSS Reflejado", "FAIL", f"Error: {e}")

    def test_sql_injection(self):
        try:
            candidatos = self._target_urls_para_inyeccion()
            payloads = WORDLISTS['security_payloads']['sql'][:6]
            sql_errors = ['sql syntax', 'mysql_fetch', 'sqlite', 'postgresql', 'oracle', 'syntax error', 'odbc driver']
            confirmados = []
            sospechosos = []
            probadas = 0
            for base_url, params in candidatos:
                for param in list(params)[:6]:
                    baseline_500 = False
                    try:
                        baseline = self.session.get(base_url, params={param: 'gl_baseline_check'}, timeout=DEFAULT_TIMEOUT)
                        baseline_500 = (baseline.status_code == 500)
                    except Exception:
                        baseline_500 = True

                    for payload in payloads:
                        probadas += 1
                        try:
                            response = self.session.get(base_url, params={param: payload}, timeout=DEFAULT_TIMEOUT)
                            cuerpo = response.text.lower()
                            if any(err in cuerpo for err in sql_errors):
                                confirmados.append(f"{param} @ {base_url}")
                                self.add_finding("Inyeccion SQL (SQLi)", f"Firma de error SQL en la respuesta al inyectar en '{param}'", base_url)
                                break
                            elif response.status_code == 500 and not baseline_500:
                                sospechosos.append(f"{param} @ {base_url}")
                                self.add_finding("Inyeccion SQL (SQLi) - Sospecha", f"Error 500 solo con payload SQL (baseline con valor inocuo respondio OK) en '{param}' - requiere confirmacion manual", base_url)
                                break
                        except Exception:
                            pass

            if confirmados:
                return self.print_result("Inyeccion SQL (SQLi)", "FAIL", f"{len(confirmados)} confirmados por firma de error (ej: {confirmados[0]}) de {probadas} pruebas")
            if sospechosos:
                return self.print_result("Inyeccion SQL (SQLi)", "WARN", f"{len(sospechosos)} sospechosos sin firma confirmada (ej: {sospechosos[0]}) - revisar manualmente")
            if probadas == 0:
                return self.print_result("Inyeccion SQL (SQLi)", "SKIP", "Sin endpoints/parametros descubiertos para probar")
            return self.print_result("Inyeccion SQL (SQLi)", "PASS", f"No se detectaron SQLi ({probadas} pruebas sobre {len(candidatos)} endpoints)")
        except Exception as e:
            return self.print_result("Inyeccion SQL (SQLi)", "FAIL", f"Error: {e}")

    def test_path_traversal(self):
        try:
            payloads = WORDLISTS['security_payloads']['path_traversal']
            candidatos = self._target_urls_para_inyeccion()
            params_traversal = {'page', 'doc', 'file', 'path', 'view', 'template', 'download'}
            vulnerables = []
            probadas = 0
            for base_url, params in candidatos:
                params_a_probar = (params & params_traversal) or {'file'}
                for param in params_a_probar:
                    for payload in payloads:
                        probadas += 1
                        try:
                            response = self.session.get(base_url, params={param: payload}, timeout=DEFAULT_TIMEOUT)
                            if any(key in response.text for key in ('root:x:', 'bin/bash', 'daemon:', '[boot loader]')):
                                vulnerables.append(f"{param} @ {base_url}")
                                self.add_finding("Directory / Path Traversal", f"Contenido de sistema expuesto via '{param}'", base_url)
                                break
                        except Exception:
                            pass

            if vulnerables:
                return self.print_result("Directory / Path Traversal", "FAIL", f"{len(vulnerables)} vulnerables (ej: {vulnerables[0]})")
            return self.print_result("Directory / Path Traversal", "PASS", f"No se detecto ({probadas} pruebas)")
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

        criticos_fail = [n for n in ('Inyeccion SQL (SQLi)', 'Directory / Path Traversal', 'Inyeccion XSS Reflejado') if self.test_statuses.get(n) == 'FAIL']
        if criticos_fail:
            nivel_riesgo, riesgo_css = ('CRITICO - Vulnerabilidad activa explotable', 'risk-critical')
        elif failed > 0:
            nivel_riesgo, riesgo_css = ('ALTO - Vulnerabilidades activas', 'risk-moderate')
        elif warns > 0:
            nivel_riesgo, riesgo_css = ('MODERADO - Requiere endurecimiento', 'risk-moderate')
        else:
            nivel_riesgo, riesgo_css = ('EXCELENTE - Postura segura', 'risk-excellent')

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

        grupos = {}
        for nombre, status in self.test_statuses.items():
            meta = TEST_METADATA.get(nombre, DEFAULT_METADATA)
            grupos.setdefault(meta['grupo'], []).append((nombre, status))

        secciones_html = []
        for grupo, pruebas in grupos.items():
            filas = []
            for nombre, status in pruebas:
                meta_status = STATUS_META.get(status, STATUS_META_DEFAULT)
                meta_test = TEST_METADATA.get(nombre, DEFAULT_METADATA)
                mensaje = html.escape(self.test_messages.get(nombre, ''))
                filas.append(f"""
                <tr>
                    <td class="col-test">{html.escape(nombre)}</td>
                    <td><span class="badge badge-{meta_status['css']}">{html.escape(status)}</span></td>
                    <td class="col-owasp">{html.escape(meta_test.get('owasp', 'General'))}</td>
                    <td class="col-msg">{mensaje}</td>
                </tr>""")
            secciones_html.append(f"""
            <div class="group-section">
                <h3>{html.escape(grupo)}</h3>
                <table>
                    <thead><tr><th>Prueba</th><th>Estado</th><th>Categoria OWASP</th><th>Detalle</th></tr></thead>
                    <tbody>{''.join(filas)}</tbody>
                </table>
            </div>""")

        orden_severidad = {'critica': 0, 'alta': 1, 'media': 2, 'baja': 3, 'info': 4}
        findings_ordenados = sorted(self.findings, key=lambda f: orden_severidad.get(f.get('severidad', 'info'), 5))
        if findings_ordenados:
            filas_f = []
            for f in findings_ordenados:
                filas_f.append(f"""
                <tr>
                    <td><span class="sev sev-{html.escape(f.get('severidad', 'info'))}">{html.escape(f.get('severidad', 'info').upper())}</span></td>
                    <td>{html.escape(f.get('test', ''))}</td>
                    <td>{html.escape(f.get('detalle', ''))}</td>
                    <td class="col-url">{html.escape(f.get('url', ''))}</td>
                </tr>""")
            findings_html = f"""
            <div class="group-section">
                <h3>Hallazgos Detallados ({failed})</h3>
                <table>
                    <thead><tr><th>Severidad</th><th>Prueba</th><th>Detalle</th><th>URL / Endpoint</th></tr></thead>
                    <tbody>{''.join(filas_f)}</tbody>
                </table>
            </div>"""
        else:
            findings_html = '<div class="group-section"><p class="no-findings">No se registraron hallazgos con detalle adicional en esta ejecucion.</p></div>'

        n_urls = len(self.crawl_data.get('visited', []))
        n_forms = len(self.crawl_data.get('forms', []))
        urls_lista = ''.join(f"<li>{html.escape(u)}</li>" for u in self.crawl_data.get('visited', [])[:25])
        auth_ok, auth_msg = self.auth_status
        descubrimiento_html = f"""
        <div class="group-section">
            <h3>Superficie Descubierta</h3>
            <p><b>URLs visitadas:</b> {n_urls} &nbsp;|&nbsp; <b>Formularios:</b> {n_forms} &nbsp;|&nbsp;
               <b>Autenticacion:</b> {'Exitosa' if auth_ok else 'No aplicada'} ({html.escape(auth_msg)})</p>
            {f'<ul class="url-list">{urls_lista}</ul>' if urls_lista else '<p class="no-findings">Sin URLs adicionales descubiertas.</p>'}
        </div>"""

        html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>GHOSTS LIGHTER - Auditoria de {html.escape(self.hostname)}</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #171a23; --border: #262b3a; --text: #e6e8ef; --muted: #8b90a3;
    --pass: #2ecc71; --warn: #f1c40f; --fail: #e74c3c; --skip: #7f8c9a; --info: #3498db;
    --accent: #6c5ce7;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }}
  header {{ text-align:center; margin-bottom: 24px; }}
  header h1 {{ font-size: 28px; margin: 0; letter-spacing: 2px; color: var(--accent); }}
  header p {{ color: var(--muted); margin: 6px 0 0; }}
  .meta-box {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin-bottom: 24px; }}
  .meta-box div {{ margin: 4px 0; }}
  .risk-banner {{ text-align:center; padding: 16px; border-radius: 10px; font-weight:600; font-size: 16px; margin-bottom: 24px; }}
  .risk-critical {{ background: rgba(231,76,60,.15); border: 1px solid var(--fail); color: var(--fail); }}
  .risk-moderate {{ background: rgba(241,196,15,.15); border: 1px solid var(--warn); color: var(--warn); }}
  .risk-good {{ background: rgba(52,152,219,.15); border: 1px solid var(--info); color: var(--info); }}
  .risk-excellent {{ background: rgba(46,204,113,.15); border: 1px solid var(--pass); color: var(--pass); }}
  .stats-grid {{ display:flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }}
  .stat-card {{ flex: 1; min-width: 110px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align:center; }}
  .stat-number {{ font-size: 28px; font-weight: 700; }}
  .stat-label {{ color: var(--muted); font-size: 12px; letter-spacing: 1px; margin-top:4px; }}
  .stat-pass .stat-number {{ color: var(--pass); }}
  .stat-warn .stat-number {{ color: var(--warn); }}
  .stat-fail .stat-number {{ color: var(--fail); }}
  .stat-skip .stat-number {{ color: var(--skip); }}
  .stat-info .stat-number {{ color: var(--info); }}
  .score-box {{ text-align:center; margin-bottom: 32px; }}
  .score-value {{ font-size: 48px; font-weight: 800; color: var(--accent); }}
  .score-label {{ color: var(--muted); }}
  .group-section {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
  .group-section h3 {{ margin-top:0; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
  table {{ width:100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align:left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .5px; }}
  .col-test {{ font-weight: 600; white-space: nowrap; }}
  .col-owasp {{ color: var(--muted); white-space: nowrap; }}
  .col-url {{ color: var(--muted); word-break: break-all; }}
  .badge {{ display:inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight:700; letter-spacing: .5px; }}
  .badge-pass {{ background: rgba(46,204,113,.15); color: var(--pass); }}
  .badge-warn {{ background: rgba(241,196,15,.15); color: var(--warn); }}
  .badge-fail {{ background: rgba(231,76,60,.15); color: var(--fail); }}
  .badge-skip {{ background: rgba(127,140,154,.15); color: var(--skip); }}
  .badge-info {{ background: rgba(52,152,219,.15); color: var(--info); }}
  .sev {{ display:inline-block; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight:700; }}
  .sev-critica {{ background: var(--fail); color: #fff; }}
  .sev-alta {{ background: rgba(231,76,60,.5); color: #fff; }}
  .sev-media {{ background: rgba(241,196,15,.4); color: #111; }}
  .sev-baja {{ background: rgba(127,140,154,.4); color: #fff; }}
  .sev-info {{ background: rgba(52,152,219,.35); color: #fff; }}
  .no-findings {{ color: var(--muted); }}
  .url-list {{ column-count: 2; font-size: 12px; color: var(--muted); max-height: 220px; overflow-y:auto; }}
  footer {{ text-align:center; color: var(--muted); font-size: 12px; margin-top: 40px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>GHOSTS LIGHTER</h1>
    <p>Reporte de Auditoria de Seguridad Web</p>
  </header>

  <div class="meta-box">
    <div><b>Objetivo:</b> {html.escape(self.target_url)}</div>
    <div><b>Fecha:</b> {ahora.strftime('%d/%m/%Y %H:%M:%S')}</div>
    <div><b>Version:</b> GHOSTS LIGHTER v{PRODUCT_VERSION}</div>
  </div>

  <div class="risk-banner {riesgo_css}">{html.escape(nivel_riesgo)}</div>

  <div class="stats-grid">{''.join(resumen_cards)}</div>

  <div class="score-box">
    <div class="score-value">{score:.1f}%</div>
    <div class="score-label">Volumen bruto de pruebas superadas sin ponderar criticidad (sobre {ejecutadas} ejecutadas, {skipped} omitidas)</div>
  </div>

  {descubrimiento_html}
  {findings_html}
  {''.join(secciones_html)}

  <footer>Reporte generado por GHOSTS LIGHTER v{PRODUCT_VERSION} &middot; OWASP Top 10:2025</footer>
</div>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_doc)
        return os.path.abspath(output_path)

    def run_audit(self, generar_html=True, output_path=None):
        print(f"{ICON_INFO} Iniciando Auditoria de Seguridad GHOSTS LIGHTER v{PRODUCT_VERSION}")
        print(f"   Objetivo: {self.target_url}")
        print("===========================================================================")

        total_fases = 15
        fase_actual = 0

        def avanzar_fase(nombre_etapa=""):
            nonlocal fase_actual
            fase_actual += 1
            barra_progreso(fase_actual, total_fases, longitud=30, prefijo="Progreso Auditoría:")
            if nombre_etapa:
                print(f"\n{ANSI_CYAN}--- [{fase_actual}/{total_fases}] {nombre_etapa} ---{ANSI_RESET}")

        avanzar_fase("Descubrimiento y Crawler")
        self.fase_descubrimiento()

        avanzar_fase("Validación de HTTPS Obligatorio")
        self.test_https_obligatorio()

        avanzar_fase("Verificación de Certificado SSL/TLS")
        self.test_ssl_certificate()

        avanzar_fase("Análisis de Headers de Seguridad")
        self.test_security_headers()

        avanzar_fase("Optimización de Archivos Estáticos")
        self.test_static_files()

        avanzar_fase("Pruebas de Inyección XSS Reflejado")
        self.test_xss_reflejado()

        avanzar_fase("Pruebas de Inyección SQL (SQLi)")
        self.test_sql_injection()

        avanzar_fase("Escaneo de Directory / Path Traversal")
        self.test_path_traversal()

        avanzar_fase("Verificación de Open Redirect")
        self.test_open_redirect()

        avanzar_fase("Evaluación de Diseño Responsive")
        self.test_diseno_responsive()

        avanzar_fase("Métricas de Performance")
        self.test_performance()

        avanzar_fase("Descubrimiento de APIs")
        self.test_api_discovery()

        avanzar_fase("Detección de Stack Tecnológico")
        self.test_tech_detection()

        avanzar_fase("Escaneo de Dependencias Expuestas")
        self.test_dependency_scan()

        avanzar_fase("Escaneo de Rutas Sensibles (Path Scan)")
        self.test_path_scan()

        total = len(self.test_results)
        passed = sum(1 for v in self.test_statuses.values() if v == 'PASS')
        warns = sum(1 for v in self.test_statuses.values() if v == 'WARN')
        failed = sum(1 for v in self.test_statuses.values() if v == 'FAIL')
        skipped = sum(1 for v in self.test_statuses.values() if v == 'SKIP')
        score = ((passed + warns) / (total - skipped) * 100) if (total - skipped) > 0 else 0

        if failed > 0:
            nivel_riesgo = 'CRITICO - Requiere atencion inmediata' if failed > 2 else 'ALTO - Vulnerabilidades activas'
        elif warns > 0:
            nivel_riesgo = 'MODERADO - Requiere endurecimiento'
        else:
            nivel_riesgo = 'BAJO - Postura aceptable'

        print(f"\n{ANSI_CYAN}=== RESUMEN DE AUDITORIA ==={ANSI_RESET}")
        print(f"   {ANSI_VERDE}PASS{ANSI_RESET}: {passed} | {ANSI_AMARILLO}WARN{ANSI_RESET}: {warns}")
        print(f"   {ANSI_ROJO}FAIL{ANSI_RESET}: {failed} | {ANSI_GRIS}SKIP{ANSI_RESET}: {skipped}")
        print(f"   Total pruebas: {total} | Ejecutadas: {total - skipped}")
        print(f"   Hallazgos detallados: {len(self.findings)} | Riesgo: {nivel_riesgo}")

        reporte_path = None
        reporte_json = None
        reporte_sarif = None

        if generar_html:
            reporter = ReporterEngine(result=self.result, target_url=self.target_url, hostname=self.hostname)
            reporte_json = reporter.generate_json()
            reporte_sarif = reporter.generate_sarif()
            reporte_path = self.generar_reporte_html(output_path)

            print(f"\n{ANSI_CYAN}=== REPORTES GENERADOS ==={ANSI_RESET}")
            print(f"   📄 HTML: {reporte_path}")
            print(f"   📊 JSON: {reporte_json}")
            print(f"   🔧 SARIF: {reporte_sarif}")

