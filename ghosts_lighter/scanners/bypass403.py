# -*- coding: utf-8 -*-
"""
Motor de detección de bypass de control de acceso en respuestas 403/401.

Técnicas soportadas:
- Header Override: cabeceras de confianza (X-Forwarded-For, X-Real-IP,
  X-Custom-IP-Authorization, Forwarded, X-HTTP-Method-Override, ...).
- URL Header Override: X-Original-URL / X-Rewrite-URL pidiendo la raiz con la
  ruta protegida en la cabecera (bypass clásico de reverse proxies).
- Verb Tampering: POST / PUT / PATCH / DELETE sobre un recurso que solo
  restringe GET.
- Path Manipulation: barra final, `/.`, `//`, sufijos codificados (%2f, %20,
  %09), prefijos `/.` y `/%2e`, mayúsculas, `;` y extensiones.

Un bypass solo se reporta cuando la respuesta pasa a 2xx, el contenido difiere
del 403 original, no coincide con el soft-404 calibrado y es reproducible.
"""

from urllib.parse import urlparse

# Rutas sensibles que suelen estar protegidas por un 401/403
SENSITIVE_PROTECTED_PATHS = [
    '/admin', '/admin/', '/administrator/', '/wp-admin/', '/admincp/',
    '/dashboard', '/console', '/api/', '/api/v1/', '/rest/',
    '/swagger/', '/docs/', '/actuator', '/server-status', '/server-info',
    '/phpmyadmin/', '/pma/', '/.env', '/.git/HEAD', '/.git/config',
    '/config.php', '/wp-config.php', '/backup/', '/backups/', '/logs/',
    '/metrics',
]

# (cabeceras, etiqueta)
BYPASS_HEADERS = [
    ({'X-Forwarded-For': '127.0.0.1'}, 'X-Forwarded-For: 127.0.0.1'),
    ({'X-Forwarded-For': 'localhost'}, 'X-Forwarded-For: localhost'),
    ({'X-Real-IP': '127.0.0.1'}, 'X-Real-IP: 127.0.0.1'),
    ({'X-Client-IP': '127.0.0.1'}, 'X-Client-IP: 127.0.0.1'),
    ({'X-Originating-IP': '127.0.0.1'}, 'X-Originating-IP: 127.0.0.1'),
    ({'X-Remote-IP': '127.0.0.1'}, 'X-Remote-IP: 127.0.0.1'),
    ({'X-Remote-Addr': '127.0.0.1'}, 'X-Remote-Addr: 127.0.0.1'),
    ({'True-Client-IP': '127.0.0.1'}, 'True-Client-IP: 127.0.0.1'),
    ({'Client-IP': '127.0.0.1'}, 'Client-IP: 127.0.0.1'),
    ({'X-Custom-IP-Authorization': '127.0.0.1'}, 'X-Custom-IP-Authorization: 127.0.0.1'),
    ({'X-Forwarded-Host': 'localhost'}, 'X-Forwarded-Host: localhost'),
    ({'X-Forwarded-Proto': 'https'}, 'X-Forwarded-Proto: https'),
    ({'Forwarded': 'for=127.0.0.1;proto=https;host=localhost'}, 'Forwarded: for=127.0.0.1'),
    ({'X-HTTP-Method-Override': 'GET'}, 'X-HTTP-Method-Override: GET'),
    ({'X-Method-Override': 'GET'}, 'X-Method-Override: GET'),
]

# Cabeceras que se evalúan pidiendo la raíz con la ruta protegida como valor
BYPASS_URL_HEADERS = ['X-Original-URL', 'X-Rewrite-URL']

BYPASS_VERBS = ['POST', 'PUT', 'PATCH', 'DELETE']

# (mutador de ruta, etiqueta)
PATH_MUTATIONS = [
    (lambda p: p + '/', 'barra final'),
    (lambda p: p + '/.', 'punto final'),
    (lambda p: p + '//', 'doble barra final'),
    (lambda p: p + '%2f', 'barra codificada (%2f)'),
    (lambda p: p + '%20', 'espacio codificado (%20)'),
    (lambda p: p + '%09', 'tabulador codificado (%09)'),
    (lambda p: '/.' + p, 'prefijo /.'),
    (lambda p: '/%2e' + p, 'prefijo /%2e'),
    (lambda p: p.upper(), 'mayusculas'),
    (lambda p: p + ';', 'punto y coma final'),
    (lambda p: p + ';/', 'punto y coma y barra final'),
    (lambda p: p + '.json', 'extension .json'),
]


class AccessControl403Scanner:
    def __init__(self, session, timeout=8, es_respuesta_real=None):
        self.session = session
        self.timeout = timeout
        # Callback opcional del orquestador para descartar soft-404 / catch-all
        self.es_respuesta_real = es_respuesta_real

    def _get(self, url, headers=None):
        try:
            return self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def _request(self, method, url):
        try:
            return self.session.request(method, url, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def _es_bypass(self, resp, baseline):
        if resp is None:
            return False
        if not (200 <= resp.status_code < 300):
            return False
        if self.es_respuesta_real is not None:
            try:
                if not self.es_respuesta_real(resp):
                    return False
            except Exception:
                pass
        cuerpo = resp.text or ''
        base_cuerpo = baseline.text or ''
        # Si el contenido sigue siendo la página de denegación, no hay bypass
        if cuerpo and base_cuerpo and cuerpo == base_cuerpo:
            return False
        return True

    def _confirmar(self, peticion, baseline):
        """Exige el bypass y su reproducibilidad antes de reportarlo."""
        if not self._es_bypass(peticion(), baseline):
            return False
        return self._es_bypass(peticion(), baseline)

    def _finding(self, url_peticion, tecnica, baseline, url_afectada):
        return {
            'technique': tecnica,
            'severity': 'critica',
            'detalle': (
                f"Bypass de control de acceso confirmado: '{url_afectada}' respondia "
                f"{baseline.status_code} y la variante '{tecnica}' respondio 2xx con contenido real"
            ),
            'evidence': f"Tecnica: {tecnica} | Peticion: {url_peticion}",
            'url': url_afectada,
            'cwe': 'CWE-284'
        }

    def scan_endpoint(self, url):
        """
        Devuelve la lista de hallazgos si la ruta responde 401/403 y alguna
        variante logra evadir el control de acceso. Vacía en caso contrario.
        """
        findings = []

        baseline = self._get(url)
        if baseline is None or baseline.status_code not in (401, 403):
            return findings

        parsed = urlparse(url)
        origen = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Cabeceras de override
        for headers, etiqueta in BYPASS_HEADERS:
            peticion = lambda h=headers: self._get(url, headers=h)
            if self._confirmar(peticion, baseline):
                findings.append(self._finding(url, f"Header Override ({etiqueta})", baseline, url))
                return findings

        # 2. Cabeceras de URL original (se pide la raiz con la ruta en la cabecera)
        for nombre in BYPASS_URL_HEADERS:
            peticion = lambda n=nombre: self._get(origen + '/', headers={n: parsed.path})
            if self._confirmar(peticion, baseline):
                findings.append(self._finding(origen + '/', f"URL Header Override ({nombre})", baseline, url))
                return findings

        # 3. Verb tampering
        for verbo in BYPASS_VERBS:
            peticion = lambda v=verbo: self._request(v, url)
            if self._confirmar(peticion, baseline):
                findings.append(self._finding(f"{verbo} {url}", f"Verb Tampering ({verbo})", baseline, url))
                return findings

        # 4. Manipulacion de ruta
        if parsed.path and parsed.path != '/':
            vistas = set()
            for mutar, etiqueta in PATH_MUTATIONS:
                ruta = mutar(parsed.path)
                if ruta == parsed.path or ruta in vistas:
                    continue
                vistas.add(ruta)
                url_mutada = f"{origen}{ruta}"
                peticion = lambda u=url_mutada: self._get(u)
                if self._confirmar(peticion, baseline):
                    findings.append(self._finding(url_mutada, f"Path Manipulation ({etiqueta})", baseline, url))
                    return findings

        return findings
