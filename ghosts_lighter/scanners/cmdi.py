# -*- coding: utf-8 -*-
"""
Motor de detección de OS Command Injection (inyección de comandos del sistema).

Técnicas soportadas:
- Output-Based: se inyecta un comando y se buscan firmas de su salida real en la
  respuesta (`uid=`/`gid=` de `id`, contenido de /etc/passwd).
- Time-Based Blind: se inyecta un retardo (`sleep N`) y se confirma midiendo el
  tiempo, con petición de control y re-verificación, para casos en los que la
  salida no se refleja.

Los payloads base se reutilizan de WORDLISTS['security_payloads']
['command_injection'] y se clasifican automáticamente según su técnica, de modo
que exista una única fuente de verdad para el catálogo de inyecciones.

Las firmas se buscan sobre la respuesta con el payload reflejado eliminado, de
forma que un endpoint que solo devuelve la entrada recibida no genere hallazgos.
"""

import re
import time
import random
from urllib.parse import quote, quote_plus

from ghosts_lighter.config import WORDLISTS

# Parámetros donde suele aterrizar entrada que acaba en el sistema operativo
CMDI_PARAM_HINTS = {
    'cmd', 'command', 'exec', 'execute', 'run', 'shell', 'ping', 'ip', 'host',
    'hostname', 'domain', 'nslookup', 'dig', 'resolve', 'dns', 'filename',
    'file', 'path', 'dir', 'directory', 'name', 'user', 'username', 'target',
    'input', 'query', 'q', 'search', 'id', 'email', 'mail', 'url', 'link',
    'address', 'server', 'port', 'format', 'convert', 'process', 'do',
    'action', 'option', 'arg', 'args', 'param', 'value', 'text', 'data'
}

# Catálogo único de payloads, clasificado por técnica
RAW_COMMAND_PAYLOADS = list(WORDLISTS['security_payloads']['command_injection'])
TIME_PAYLOADS = [p for p in RAW_COMMAND_PAYLOADS if re.search(r'\bsleep\b', p, re.I)]
OUTPUT_PAYLOADS = [p for p in RAW_COMMAND_PAYLOADS if p not in TIME_PAYLOADS]

# Firmas de salida de comandos del sistema
OUTPUT_SIGNATURES = [
    (re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)", re.I), "salida completa de 'id' (Linux)"),
    (re.compile(r"uid=\d+\([^)]+\)", re.I), "salida de 'id' (Linux)"),
    (re.compile(r"root:[x*]:0:0:", re.I), "contenido de /etc/passwd (root)"),
    (re.compile(r"\bdaemon:[x*]:[0-9]+:[0-9]+:", re.I), "contenido de /etc/passwd (daemon)"),
]

# Tolerancia al comparar el retardo observado con el esperado
TOLERANCIA_SLEEP = 1.0


class CommandInjectionScanner:
    def __init__(self, session, timeout=8, time_based=True):
        self.session = session
        self.timeout = timeout
        self.time_based = time_based

    @staticmethod
    def _limpiar_reflejo(texto, payload):
        """Elimina el payload reflejado (crudo y URL-encoded) antes de buscar firmas."""
        limpio = texto.replace(payload, '')
        for variante in (quote(payload, safe=''), quote_plus(payload, safe='')):
            if variante and variante != payload:
                limpio = limpio.replace(variante, '')
        return limpio

    @staticmethod
    def _firma_presente(texto):
        for patron, desc in OUTPUT_SIGNATURES:
            if patron.search(texto):
                return desc
        return None

    @staticmethod
    def _sleep_seconds(payload):
        match = re.search(r'\bsleep\s+(\d+)', payload, re.I)
        return int(match.group(1)) if match else 3

    def scan_endpoint(self, base_url, param):
        """
        Ejecuta análisis completo de Command Injection sobre un parámetro:
        1. Output-Based con confirmación determinista.
        2. Time-Based Blind con control y re-verificación.
        """
        findings = []

        try:
            t0 = time.perf_counter()
            baseline = self.session.get(base_url, params={param: f"glcmdi{random.randint(1000, 9999)}"}, timeout=self.timeout)
            baseline_time = time.perf_counter() - t0
            baseline_text = baseline.text or ''
        except Exception:
            return findings

        # Si la página ya contiene algo que parece salida de comando, no es fiable
        if self._firma_presente(baseline_text):
            return findings

        # 1. Output-Based
        for payload in OUTPUT_PAYLOADS:
            try:
                resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
            except Exception:
                continue
            firma = self._firma_presente(self._limpiar_reflejo(resp.text or '', payload))
            if not firma:
                continue

            # Confirmación determinista
            try:
                resp2 = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
            except Exception:
                continue
            if not self._firma_presente(self._limpiar_reflejo(resp2.text or '', payload)):
                continue

            findings.append({
                'technique': 'Output-Based',
                'severity': 'critica',
                'detalle': f"OS Command Injection confirmada en parametro '{param}': la inyeccion '{payload}' produjo {firma} en la respuesta",
                'evidence': f"Payload: {payload} | Firma: {firma}",
                'url': base_url,
                'cwe': 'CWE-78'
            })
            return findings

        # 2. Time-Based Blind
        if not self.time_based:
            return findings

        for payload in TIME_PAYLOADS:
            esperado = self._sleep_seconds(payload)
            umbral = baseline_time + esperado - TOLERANCIA_SLEEP

            try:
                t0 = time.perf_counter()
                self.session.get(base_url, params={param: payload}, timeout=self.timeout + esperado + 2)
                elapsed = time.perf_counter() - t0
            except Exception:
                continue
            if elapsed < umbral:
                continue

            # Control: una petición normal no debe tardar
            try:
                t_ctrl = time.perf_counter()
                self.session.get(base_url, params={param: f"glctrl{random.randint(1000, 9999)}"}, timeout=self.timeout)
                if time.perf_counter() - t_ctrl >= 2.0:
                    continue
            except Exception:
                continue

            # Re-verificación del retardo
            try:
                t1 = time.perf_counter()
                self.session.get(base_url, params={param: payload}, timeout=self.timeout + esperado + 2)
                elapsed_confirm = time.perf_counter() - t1
            except Exception:
                continue
            if elapsed_confirm < umbral:
                continue

            findings.append({
                'technique': 'Time-Based Blind',
                'severity': 'critica',
                'detalle': f"OS Command Injection ciega confirmada en parametro '{param}': retardo de {esperado}s reproducido ({elapsed:.2f}s y {elapsed_confirm:.2f}s vs baseline {baseline_time:.2f}s) con '{payload}'",
                'evidence': f"Payload: {payload} | Elapsed: {elapsed:.2f}s, Confirm: {elapsed_confirm:.2f}s",
                'url': base_url,
                'cwe': 'CWE-78'
            })
            break

        return findings
