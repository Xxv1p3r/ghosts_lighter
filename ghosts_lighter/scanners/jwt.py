# -*- coding: utf-8 -*-
"""
Motor de auditoría de JWT (JSON Web Tokens).

Análisis offline (sobre el token, sin enviarlo a ningún sitio):
- Tokens sin firma: `alg: none` o segmento de firma vacío.
- Secreto HMAC débil: se recalcula la firma con un diccionario de secretos
  habituales. Una coincidencia es una **prueba criptográfica**, no una
  heurística: no puede dar un falso positivo.
- Claims sensibles expuestos en el payload.
- Ausencia de expiración (`exp`).

Análisis activo (solo si hay un endpoint de prueba autenticado):
- Aceptación de un token forjado con `alg: none`.
- Ausencia de validación de firma, usando como control un token con la firma
  manipulada (que debería ser rechazado).
"""

import base64
import hashlib
import hmac
import json
import re

from ghosts_lighter.config import JWT_WEAK_SECRETS

# Un JWT siempre empieza por `eyJ` (base64url de '{"'), dos veces
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*')

SENSITIVE_CLAIMS = re.compile(
    r'"[A-Za-z0-9_]*(?:password|passwd|secret|token|apikey|api_key|ssn|'
    r'creditcard|credit_card|private|pin)[A-Za-z0-9_]*"',
    re.I
)

HMAC_ALGS = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def es_jwt(valor):
    """True si el valor completo tiene forma de JWT."""
    return bool(valor) and bool(JWT_RE.fullmatch(valor))


def extraer_jwts(texto):
    """Extrae todos los JWT presentes en un texto."""
    return JWT_RE.findall(texto or '')


def _b64url_decode(segmento):
    relleno = '=' * (-len(segmento) % 4)
    return base64.urlsafe_b64decode(segmento + relleno)


def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


class JWTScanner:
    def __init__(self, session=None, timeout=8, secretos=None):
        self.session = session
        self.timeout = timeout
        self.secretos = list(secretos) if secretos else list(JWT_WEAK_SECRETS)

    @staticmethod
    def decodificar(token):
        """Decodifica header y payload sin verificar la firma."""
        partes = (token or '').split('.')
        if len(partes) != 3:
            return None
        try:
            header = json.loads(_b64url_decode(partes[0]))
            payload = json.loads(_b64url_decode(partes[1]))
        except Exception:
            return None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return {'header': header, 'payload': payload, 'signature': partes[2]}

    def romper_hmac(self, token):
        """Devuelve el secreto si la firma valida con alguno del diccionario."""
        partes = (token or '').split('.')
        if len(partes) != 3 or not partes[2]:
            return None

        decodificado = self.decodificar(token)
        if not decodificado:
            return None
        funcion = HMAC_ALGS.get(str(decodificado['header'].get('alg', '')).upper())
        if funcion is None:
            return None

        mensaje = f"{partes[0]}.{partes[1]}".encode()
        for secreto in self.secretos:
            calculada = _b64url_encode(hmac.new(secreto.encode(), mensaje, funcion).digest())
            if hmac.compare_digest(calculada, partes[2]):
                return secreto
        return None

    @staticmethod
    def forjar_alg_none(token):
        """Devuelve el token con la cabecera cambiada a alg=none y sin firma."""
        partes = (token or '').split('.')
        if len(partes) != 3:
            return None
        cabecera = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(',', ':')).encode())
        return f"{cabecera}.{partes[1]}."

    @staticmethod
    def forjar_firma_invalida(token):
        """Devuelve el token con la firma manipulada (control negativo)."""
        partes = (token or '').split('.')
        if len(partes) != 3:
            return None
        return f"{partes[0]}.{partes[1]}.glssterminacioninvalida0000000000"

    def analyze(self, token, origen='desconocido'):
        """Analisis offline del token. Cada finding lleva su clave 'test'."""
        findings = []
        decodificado = self.decodificar(token)
        if not decodificado:
            return findings

        header = decodificado['header']
        payload = decodificado['payload']
        alg = str(header.get('alg', '')).lower()

        # 1. Token sin firma
        if alg in ('none', '') or not decodificado['signature']:
            findings.append({
                'test': 'JWT Sin Firma (alg none)',
                'technique': 'Unsigned Token',
                'severity': 'critica',
                'detalle': f"Token JWT sin firma (alg='{alg or 'vacio'}') en {origen}: cualquier payload puede ser forjado",
                'evidence': f"Origen: {origen} | alg: {alg or 'vacio'} | firma: {'vacia' if not decodificado['signature'] else 'presente'}",
                'url': origen,
                'cwe': 'CWE-347'
            })

        # 2. Secreto HMAC debil (prueba criptografica)
        secreto = self.romper_hmac(token)
        if secreto is not None:
            findings.append({
                'test': 'JWT Secreto HMAC Debil',
                'technique': f"HMAC Secret Cracked ({header.get('alg')})",
                'severity': 'critica',
                'detalle': f"Firma HMAC de {origen} validada con el secreto debil '{secreto}': un atacante puede firmar tokens arbitrarios",
                'evidence': f"Origen: {origen} | alg: {header.get('alg')} | secreto: {secreto}",
                'url': origen,
                'cwe': 'CWE-798'
            })

        # 3. Claims sensibles en el payload
        sensibles = sorted(set(SENSITIVE_CLAIMS.findall(json.dumps(payload))))
        if sensibles:
            nombres = ', '.join(s.strip('"') for s in sensibles[:6])
            findings.append({
                'test': 'JWT Claims Sensibles',
                'technique': 'Sensitive Claims',
                'severity': 'media',
                'detalle': f"El payload de {origen} expone claims potencialmente sensibles: {nombres}",
                'evidence': f"Origen: {origen} | claims: {nombres}",
                'url': origen,
                'cwe': 'CWE-200'
            })

        # 4. Sin expiracion
        if 'exp' not in payload:
            findings.append({
                'test': 'JWT Sin Expiracion',
                'technique': 'No Expiration',
                'severity': 'baja',
                'detalle': f"El token de {origen} no declara expiracion ('exp'): si se filtra, es valido indefinidamente",
                'evidence': f"Origen: {origen} | claims: {', '.join(sorted(payload.keys()))}",
                'url': origen,
                'cwe': 'CWE-613'
            })

        return findings

    def _pedir(self, probe_url, token, transporte, nombre):
        try:
            if transporte == 'cookie':
                return self.session.get(probe_url, cookies={nombre: token}, timeout=self.timeout)
            return self.session.get(probe_url, headers={'Authorization': f'Bearer {token}'}, timeout=self.timeout)
        except Exception:
            return None

    @staticmethod
    def _similar(a, b):
        la, lb = len(a.text or ''), len(b.text or '')
        if la == 0 and lb == 0:
            return True
        return abs(la - lb) / max(la, lb, 1) < 0.25

    def test_alg_none_aceptado(self, probe_url, token, transporte='cookie', nombre=None):
        """
        Comprueba si el servidor acepta un token forjado con alg=none sobre un
        endpoint que sí responde al token legitimo.
        """
        findings = []
        if self.session is None or (transporte == 'cookie' and not nombre):
            return findings

        baseline = self._pedir(probe_url, token, transporte, nombre)
        if baseline is None or not (200 <= baseline.status_code < 300):
            return findings

        forjado = self.forjar_alg_none(token)
        resp_forjado = self._pedir(probe_url, forjado, transporte, nombre)
        if resp_forjado is None or not (200 <= resp_forjado.status_code < 300):
            return findings
        if not self._similar(baseline, resp_forjado):
            return findings

        # Control negativo: una firma manipulada NO deberia ser aceptada
        manipulado = self.forjar_firma_invalida(token)
        resp_control = self._pedir(probe_url, manipulado, transporte, nombre)
        if resp_control is not None and 200 <= resp_control.status_code < 300 and self._similar(baseline, resp_control):
            findings.append({
                'test': 'JWT Firma No Validada',
                'technique': 'Signature Not Verified',
                'severity': 'critica',
                'detalle': f"El servidor acepta tokens con la firma manipulada en {probe_url}: la firma JWT no se valida en absoluto",
                'evidence': f"Probe: {probe_url} | token forjado y token con firma invalida aceptados",
                'url': probe_url,
                'cwe': 'CWE-347'
            })
            return findings

        findings.append({
            'test': 'JWT Sin Firma (alg none)',
            'technique': 'alg=none Accepted',
            'severity': 'critica',
            'detalle': f"El servidor acepta un token forjado con alg=none en {probe_url}: se puede suplantar cualquier identidad sin conocer la clave",
            'evidence': f"Probe: {probe_url} | el token legitimo y el forjado con alg=none reciben la misma respuesta",
            'url': probe_url,
            'cwe': 'CWE-347'
        })
        return findings
