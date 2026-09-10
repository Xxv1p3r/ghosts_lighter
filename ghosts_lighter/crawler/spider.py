# -*- coding: utf-8 -*-
"""
Crawler web con soporte para descubrimiento SPA y análisis estático de JS.
"""

import re
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from ghosts_lighter.config import (
    DEFAULT_TIMEOUT,
    JS_PATTERNS,
    MAX_JS_BUNDLE_BYTES,
    MAX_JS_BUNDLES
)

try:
    from playwright.sync_api import sync_playwright
    BROWSER_AVAILABLE = True
except ImportError:
    sync_playwright = None
    BROWSER_AVAILABLE = False

class Crawler:
    LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
    FORM_ATTR_RE = re.compile(r'(action|method)=["\']([^"\']*)["\']', re.I)
    INPUT_RE = re.compile(r'<input\b([^>]*)>', re.I)
    NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.I)
    TYPE_RE = re.compile(r'type=["\']([^"\']+)["\']', re.I)
    _PATRON_BAJA_PRIORIDAD = re.compile(r'(vendor|polyfill|runtime|chunk-vendors|node_modules|jquery|lodash|moment)', re.I)

    def __init__(self, session, base_url, max_pages=40, max_depth=2, use_selenium=False, debug_mode=False):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.hostname = urlparse(base_url).hostname
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.use_selenium = use_selenium and BROWSER_AVAILABLE
        self.debug_mode = debug_mode
        self.visited = set()
        self.pages = {}
        self.forms = []
        self.query_params = {}
        self._playwright = None
        self._browser = None
        self.js_endpoints = set()
        self.js_secrets = []
        self.js_bundles_analizados = 0
        self.js_bundles_descubiertos = 0
        self.js_bundles_omitidos = 0

    def _same_site(self, url):
        try:
            return urlparse(url).hostname in (self.hostname, None)
        except Exception:
            return False

    def _normalize(self, url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

    def _extract_links(self, html_text, current_url):
        out = set()
        for m in self.LINK_RE.finditer(html_text):
            href = m.group(1)
            if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                continue
            full = urljoin(current_url, href)
            if self._same_site(full):
                out.add(full)
        return out

    def _extract_forms(self, html_text, current_url):
        found = []
        for m in self.FORM_RE.finditer(html_text):
            attrs_str = m.group(1)
            body = m.group(2)
            attrs = dict((k.lower(), v) for k, v in self.FORM_ATTR_RE.findall(attrs_str))
            action = urljoin(current_url, attrs.get('action', current_url))
            method = attrs.get('method', 'get').upper()
            fields = []
            for inp in self.INPUT_RE.finditer(body):
                inp_attrs = inp.group(1)
                name_m = self.NAME_RE.search(inp_attrs)
                type_m = self.TYPE_RE.search(inp_attrs)
                if name_m:
                    fields.append({
                        'name': name_m.group(1),
                        'type': type_m.group(1).lower() if type_m else 'text'
                    })
            if fields:
                found.append({
                    'action': action,
                    'method': method,
                    'fields': fields,
                    'source': current_url
                })
        return found

    def _extract_script_refs(self, html_text, current_url):
        externos = set()
        inline = []
        for m in re.finditer(r'<script\b([^>]*)>(.*?)</script>', html_text, re.I | re.S):
            attrs = m.group(1)
            body = m.group(2)
            src_m = re.search(r'src=["\']([^"\']+)["\']', attrs, re.I)
            if src_m:
                src = src_m.group(1)
                if '.js' in src.lower():
                    externos.add(urljoin(current_url, src))
            elif body.strip():
                inline.append(body)
        return externos, inline

    @staticmethod
    def _redactar_secreto(valor):
        if len(valor) <= 8:
            return '*' * len(valor)
        return f"{valor[:4]}{'*' * (len(valor) - 8)}{valor[-4:]}"

    def _escanear_texto_js(self, texto, fuente):
        for m in JS_PATTERNS['api_endpoints'].finditer(texto):
            self.js_endpoints.add(m.group(1))
        for m in JS_PATTERNS['secrets'].finditer(texto):
            tipo = m.group(1)
            valor = m.group(2)
            self.js_secrets.append({
                'tipo': tipo,
                'valor_redactado': self._redactar_secreto(valor),
                'fuente': fuente
            })

    def _priorizar_bundles(self, urls):
        def prioridad(url):
            nombre = urlparse(url).path.lower()
            if self._PATRON_BAJA_PRIORIDAD.search(nombre):
                return 2
            if re.search(r'(main|app|index|bundle)', nombre):
                return 0
            return 1
        return sorted(urls, key=prioridad)

    def analizar_js(self):
        externos_totales = set()
        inline_totales = []
        for url, body in self.pages.items():
            if body:
                ext, inl = self._extract_script_refs(body, url)
                externos_totales |= ext
                inline_totales.extend(inl)
        externos_priorizados = self._priorizar_bundles(externos_totales)
        self.js_bundles_descubiertos = len(externos_priorizados) + len(inline_totales)
        self.js_bundles_omitidos = max(0, len(externos_priorizados) - MAX_JS_BUNDLES) + max(0, len(inline_totales) - MAX_JS_BUNDLES)

        for js_url in externos_priorizados[:MAX_JS_BUNDLES]:
            try:
                resp = self.session.get(js_url, timeout=DEFAULT_TIMEOUT, stream=True)
                contenido = resp.raw.read(MAX_JS_BUNDLE_BYTES + 1, decode_content=True)
                if len(contenido) > MAX_JS_BUNDLE_BYTES:
                    contenido = contenido[:MAX_JS_BUNDLE_BYTES]
                texto = contenido.decode('utf-8', errors='ignore')
                self.js_bundles_analizados += 1
                self._escanear_texto_js(texto, js_url)
            except Exception:
                pass

        for idx, bloque in enumerate(inline_totales[:MAX_JS_BUNDLES]):
            self.js_bundles_analizados += 1
            self._escanear_texto_js(bloque[:MAX_JS_BUNDLE_BYTES], f'inline#{idx}')

        return {
            'endpoints': sorted(self.js_endpoints),
            'secrets': self.js_secrets,
            'bundles_analizados': self.js_bundles_analizados,
            'bundles_descubiertos': self.js_bundles_descubiertos,
            'bundles_omitidos': self.js_bundles_omitidos
        }

    def _browser_links(self, url):
        page = None
        try:
            if self._playwright is None:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(headless=True)
            page = self._browser.new_page()
            page.goto(url, timeout=DEFAULT_TIMEOUT * 1000, wait_until='networkidle')
            page.wait_for_timeout(1000)
            rendered_html = page.content()
            hrefs = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            links = {h for h in hrefs if h and self._same_site(h)}
            page.close()
            return rendered_html, links
        except Exception:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            return '', set()

    def close(self):
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                pass

    def crawl(self):
        queue = deque([(self.base_url, 0)])
        seen = {self._normalize(self.base_url)}
        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            norm = self._normalize(url)
            if norm in self.visited or depth > self.max_depth:
                continue
            body_text = ''
            links = set()
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                body_text = resp.text or ''
                links |= self._extract_links(body_text, url)
            except Exception:
                pass

            if self.use_selenium:
                rendered, js_links = self._browser_links(url)
                if rendered and len(rendered) > len(body_text):
                    body_text = rendered
                links |= js_links

            self.visited.add(norm)
            self.pages[url] = body_text
            self.forms.extend(self._extract_forms(body_text, url))
            parsed_q = parse_qs(urlparse(url).query)
            if parsed_q:
                self.query_params.setdefault(self._normalize(url), set()).update(parsed_q.keys())

            for link in links:
                link_norm = self._normalize(link)
                if link_norm not in seen and len(seen) < self.max_pages * 3:
                    seen.add(link_norm)
                    queue.append((link, depth + 1))

        self.close()
        js_resultado = self.analizar_js()
        return {
            'visited': sorted(self.visited),
            'forms': self.forms,
            'query_params': self.query_params,
            'js_endpoints': js_resultado['endpoints'],
            'js_secrets': js_resultado['secrets'],
            'js_bundles_analizados': js_resultado['bundles_analizados'],
            'js_bundles_descubiertos': js_resultado['bundles_descubiertos'],
            'js_bundles_omitidos': js_resultado['bundles_omitidos']
        }

