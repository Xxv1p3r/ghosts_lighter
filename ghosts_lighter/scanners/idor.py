# -*- coding: utf-8 -*-
"""
Motor de detección de IDOR (Insecure Direct Object Reference) y BOLA (Broken Object Level Authorization).

Soporta:
- Doble sesión autenticada (Usuario A vs Usuario B - Escalada Horizontal de Privilegios).
- Sesión autenticada vs Sesión anónima/invitado (Usuario A vs Guest - Escalada Vertical de Privilegios).
- Detección en parámetros de consulta (Query Params: ?id=1, ?user_id=12, ?account=..., etc.).
- Detección en rutas RESTful (/api/users/1, /orders/105, /profile/admin, etc.).
- Tampering de identificadores (mutación secuencial de IDs para verificar falta de autorización sobre objetos ajenos).
- Validación anti-falsos positivos con filtrado de Soft-404, detección de formularios/redirecciones de login y comprobación diferencial de contenido.
"""

import re
import json
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Parámetros típicamente asociados a identificación de objetos o recursos privados
IDOR_PARAM_HINTS = {
    'id', 'user_id', 'userid', 'user', 'uid', 'account_id', 'account',
    'profile_id', 'profile', 'order_id', 'order', 'doc_id', 'doc',
    'document_id', 'document', 'invoice_id', 'invoice', 'item_id', 'item',
    'ticket_id', 'ticket', 'customer_id', 'customer', 'member_id', 'member',
    'client_id', 'client', 'record_id', 'record', 'file_id', 'report_id',
    'report', 'transaction_id', 'tx_id', 'bill_id', 'booking_id', 'key',
    'number', 'no', 'num', 'ref', 'reference'
}

# Rutas típicas que exponen objetos de usuario / recursos privados
COMMON_OBJECT_PATHS = [
    '/api/user/1',
    '/api/users/1',
    '/api/v1/users/1',
    '/api/profile',
    '/api/account',
    '/api/orders/1',
    '/users/1',
    '/profile?id=1',
    '/account?id=1',
    '/order?id=1',
    '/invoice?id=1',
]

# Expresiones regulares para identificar segmentos RESTful con identificadores
REST_ID_PATTERNS = [
    re.compile(
        r'(/(?:api(?:/v\d+)?)?/(?:users?|accounts?|profiles?|orders?|items?|invoices?|documents?|tickets?|customers?|members?|files?|transactions?|bookings?|records?))/([a-zA-Z0-9_\-]+)',
        re.I
    ),
]

# Indicadores de formulario o pantalla de login / acceso denegado en respuestas 200
LOGIN_INDICATORS = [
    re.compile(r'<input\b[^>]*type=["\']password["\']', re.I),
    re.compile(r'\b(iniciar sesion|inicie sesion|login|sign in|please log in|unauthorized access|acceso no autorizado)\b', re.I),
]


def _es_formulario_login(resp):
    """Detecta si una respuesta HTTP contiene una pantalla de login o formulario de autenticación."""
    if resp is None:
        return False
    # Verificar cabecera Location en redirecciones
    loc = resp.headers.get('Location', '') if hasattr(resp, 'headers') else ''
    if loc and any(k in loc.lower() for k in ('login', 'auth', 'signin', 'unauthorized')):
        return True
    texto = (resp.text or '').lower()
    return any(p.search(texto) for p in LOGIN_INDICATORS)


def _tamper_id(val):
    """Genera un identificador mutado para pruebas de tampering secuencial."""
    if val.isdigit():
        num = int(val)
        return str(num + 1) if num != 0 else '1'
    if val.lower() == 'admin':
        return 'user'
    if val.lower() in ('user', 'test'):
        return 'admin'
    return '1' if val != '1' else '2'


class IDORScanner:
    def __init__(self, session_a, session_b=None, timeout=8, es_respuesta_real=None, session_b_authenticated=False):
        """
        :param session_a: Sesión primaria (autenticada como Usuario A o sesión base).
        :param session_b: Sesión secundaria (Usuario B autenticado o anónima/invitado).
        :param timeout: Timeout en segundos para peticiones HTTP.
        :param es_respuesta_real: Callback para descartar soft-404 / catch-all.
        :param session_b_authenticated: Indica si session_b corresponde a un segundo usuario autenticado.
        """
        self.session_a = session_a
        if session_b is None:
            import requests
            self.session_b = requests.Session()
            self.session_b.verify = False
            self.session_b_authenticated = False
        else:
            self.session_b = session_b
            self.session_b_authenticated = session_b_authenticated
        self.timeout = timeout
        self.es_respuesta_real = es_respuesta_real

    def _get(self, session, url, headers=None):
        try:
            return session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def _es_objeto_valido(self, resp):
        """Verifica si la respuesta base de Sesión A corresponde a un recurso/objeto privado válido."""
        if resp is None:
            return False
        if not (200 <= resp.status_code < 300):
            return False
        if _es_formulario_login(resp):
            return False
        if self.es_respuesta_real is not None:
            try:
                if not self.es_respuesta_real(resp):
                    return False
            except Exception:
                pass
        cuerpo = (resp.text or '').strip()
        if len(cuerpo) < 15:
            return False
        return True

    def _indica_idor(self, resp_a, resp_b):
        """
        Determina si la respuesta de Sesión B frente al objeto de Sesión A evidencia
        una falta de control de acceso a nivel de objeto (IDOR / BOLA).
        """
        if resp_b is None:
            return False
        # Si la sesión B recibe 401, 403, 404 o redirección a login, el control es adecuado
        if resp_b.status_code in (401, 403, 404):
            return False
        if not (200 <= resp_b.status_code < 300):
            return False
        # Descartar si Sesión B recibió una redirección o formulario de login
        if _es_formulario_login(resp_b):
            return False
        # Descartar soft-404 o fallback SPA en Sesión B
        if self.es_respuesta_real is not None:
            try:
                if not self.es_respuesta_real(resp_b):
                    return False
            except Exception:
                pass

        cuerpo_a = resp_a.text or ''
        cuerpo_b = resp_b.text or ''

        # Caso 1: Respuestas JSON (APIs REST)
        try:
            json_a = json.loads(cuerpo_a)
            json_b = json.loads(cuerpo_b)
            if isinstance(json_b, (dict, list)) and len(json_b) > 0:
                if isinstance(json_b, dict):
                    if any(k.lower() in ('error', 'err', 'unauthorized', 'forbidden') for k in json_b.keys()):
                        return False
                # Si el contenido JSON es idéntico o comparte estructura con datos de A
                if json_a == json_b:
                    return True
                if isinstance(json_a, dict) and isinstance(json_b, dict):
                    shared = set(json_a.keys()) & set(json_b.keys())
                    if len(shared) >= 2:
                        return True
        except Exception:
            pass

        # Caso 2: Respuestas HTML / Texto
        if cuerpo_a == cuerpo_b:
            return True

        similarity = SequenceMatcher(None, cuerpo_a, cuerpo_b).ratio()
        if similarity >= 0.70 and len(cuerpo_b.strip()) >= 50:
            # Descartar páginas de error genérico
            lower_b = cuerpo_b.lower()
            if not any(e in lower_b for e in ('access denied', 'acceso denegado', 'unauthorized', 'not found', 'no encontrado')):
                return True

        return False

    def _confirmar(self, url, resp_a):
        """Re-verifica la petición con Sesión B para asegurar reproducibilidad."""
        resp_b = self._get(self.session_b, url)
        if not self._indica_idor(resp_a, resp_b):
            return None
        # Segunda confirmación
        resp_b_re = self._get(self.session_b, url)
        if self._indica_idor(resp_a, resp_b_re):
            return resp_b_re
        return None

    def _finding(self, url, tecnica, resp_a, resp_b, param=None, detalle_extra=None):
        rol_b = "Usuario B (Sesion Secundaria)" if self.session_b_authenticated else "Invitado (Sesion Anonima)"
        evidencia = f"Sesion A [HTTP {resp_a.status_code}] vs Sesion B ({rol_b}) [HTTP {resp_b.status_code}]"
        if detalle_extra:
            evidencia += f" | {detalle_extra}"
        cuerpo_preview = (resp_b.text or '')[:120].replace('\n', ' ').strip()
        if cuerpo_preview:
            evidencia += f" | Datos: {cuerpo_preview}..."

        desc = (
            f"Vulnerabilidad IDOR / BOLA ({tecnica}) confirmada en '{url}': "
            f"La sesion '{rol_b}' accedio al recurso privado con HTTP {resp_b.status_code} "
            f"sin validacion de autorizacion a nivel de objeto."
        )
        if param:
            desc += f" Parametro afectado: '{param}'."

        return {
            'test': 'Auditoria IDOR (Doble Sesion)',
            'technique': tecnica,
            'severity': 'critica',
            'detalle': desc,
            'evidence': evidencia,
            'url': url,
            'param': param,
            'cwe': 'CWE-639'
        }

    def scan_endpoint(self, url, param=None):
        """
        Escanea una URL específica en busca de IDOR/BOLA.
        Evalúa acceso cruzado entre sesiones y manipulación de identificadores.
        Devuelve una lista de hallazgos (vacía si es seguro).
        """
        findings = []

        # 1. Escaneo de parámetro en Query String
        if param:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if param in qs:
                baseline_a = self._get(self.session_a, url)
                if not self._es_objeto_valido(baseline_a):
                    return findings

                # Prueba A: Sesión B accediendo exactamente al objeto de Sesión A
                tecnica = "Cross-Session Object Access (Horizontal BOLA)" if self.session_b_authenticated else "Unauthenticated Object Access (Vertical BOLA)"
                resp_b_conf = self._confirmar(url, baseline_a)
                if resp_b_conf:
                    findings.append(self._finding(url, tecnica, baseline_a, resp_b_conf, param=param))

                # Prueba B: Manipulación (Tampering) del identificador de parámetro
                val_actual = qs[param][0] if qs[param] else '1'
                val_mutado = _tamper_id(val_actual)
                if val_mutado != val_actual:
                    qs_mutada = dict(qs)
                    qs_mutada[param] = [val_mutado]
                    url_tampered = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(qs_mutada, doseq=True), parsed.fragment
                    ))
                    resp_a_tampered = self._get(self.session_a, url_tampered)
                    if self._es_objeto_valido(resp_a_tampered):
                        resp_b_tampered = self._confirmar(url_tampered, resp_a_tampered)
                        if resp_b_tampered:
                            tecnica_tamper = f"Parameter Tampering IDOR ({param}={val_actual}->{val_mutado})"
                            findings.append(self._finding(
                                url_tampered, tecnica_tamper, resp_a_tampered, resp_b_tampered,
                                param=param, detalle_extra=f"Tampering: {param}={val_mutado}"
                            ))
                        elif resp_a_tampered.text != baseline_a.text:
                            tecnica_tamper = f"Parameter Tampering IDOR ({param}={val_actual}->{val_mutado})"
                            findings.append(self._finding(
                                url_tampered, tecnica_tamper, baseline_a, resp_a_tampered,
                                param=param, detalle_extra=f"Sesión A accedió a recurso ajeno {param}={val_mutado}"
                            ))
            return findings

        # 2. Escaneo de ruta RESTful con identificador en el path
        parsed = urlparse(url)
        path = parsed.path
        rest_match = None
        for pattern in REST_ID_PATTERNS:
            m = pattern.search(path)
            if m:
                rest_match = m
                break

        baseline_a = self._get(self.session_a, url)
        if not self._es_objeto_valido(baseline_a):
            return findings

        # Prueba A: Sesión B solicitando el mismo endpoint REST
        tecnica = "Cross-Session REST IDOR (Horizontal BOLA)" if self.session_b_authenticated else "Unauthenticated REST IDOR (Vertical BOLA)"
        resp_b_conf = self._confirmar(url, baseline_a)
        if resp_b_conf:
            findings.append(self._finding(url, tecnica, baseline_a, resp_b_conf))

        # Prueba B: Tampering en el segmento REST si se identificó un ID en la ruta
        if rest_match:
            prefijo = rest_match.group(1)
            id_actual = rest_match.group(2)
            id_mutado = _tamper_id(id_actual)
            if id_mutado != id_actual:
                nueva_ruta = path[:rest_match.start()] + f"{prefijo}/{id_mutado}" + path[rest_match.end():]
                url_tampered = urlunparse((
                    parsed.scheme, parsed.netloc, nueva_ruta,
                    parsed.params, parsed.query, parsed.fragment
                ))
                resp_a_tampered = self._get(self.session_a, url_tampered)
                if self._es_objeto_valido(resp_a_tampered):
                    resp_b_tampered = self._confirmar(url_tampered, resp_a_tampered)
                    if resp_b_tampered:
                        tecnica_tamper = f"REST Path Tampering IDOR ({id_actual}->{id_mutado})"
                        findings.append(self._finding(
                            url_tampered, tecnica_tamper, resp_a_tampered, resp_b_tampered,
                            detalle_extra=f"Path Tampering: {prefijo}/{id_mutado}"
                        ))
                    elif resp_a_tampered.text != baseline_a.text:
                        tecnica_tamper = f"REST Path Tampering IDOR ({id_actual}->{id_mutado})"
                        findings.append(self._finding(
                            url_tampered, tecnica_tamper, baseline_a, resp_a_tampered,
                            detalle_extra=f"Sesión A accedió a recurso ajeno {prefijo}/{id_mutado}"
                        ))

        return findings
