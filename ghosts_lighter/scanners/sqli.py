# -*- coding: utf-8 -*-
"""
Motor avanzado de detección de SQL Injection (SQLi).
Soporta:
- Error-Based SQLi (Firmas de múltiples motores de BD)
- Boolean-Based Blind SQLi (Diferencial True/False)
- Time-Based Blind SQLi (Retardo medido con confirmación contra lag)
"""

import time
import re
from difflib import SequenceMatcher

# Firmas regex de errores de bases de datos
SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL / MariaDB"),
    (re.compile(r"warning:\s+mysql_", re.I), "MySQL / MariaDB"),
    (re.compile(r"valid mysql result", re.I), "MySQL / MariaDB"),
    (re.compile(r"check the manual that corresponds to your (mysql|mariadb)", re.I), "MySQL / MariaDB"),
    (re.compile(r"MySqlClient\.", re.I), "MySQL .NET"),
    # PostgreSQL
    (re.compile(r"pg_query\(\)\s*:", re.I), "PostgreSQL"),
    (re.compile(r"postgresql.*error", re.I), "PostgreSQL"),
    (re.compile(r"syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string at or near", re.I), "PostgreSQL"),
    (re.compile(r"PSQLException", re.I), "PostgreSQL JDBC"),
    # SQLite
    (re.compile(r"sqlite3::", re.I), "SQLite"),
    (re.compile(r"operationalerror:\s*near", re.I), "SQLite"),
    (re.compile(r"sqlite_exception", re.I), "SQLite"),
    (re.compile(r"unrecognized token:", re.I), "SQLite"),
    # Microsoft SQL Server
    (re.compile(r"driver.*sql[\-\_\ ]*server", re.I), "Microsoft SQL Server"),
    (re.compile(r"ole db.*sql server", re.I), "Microsoft SQL Server"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "Microsoft SQL Server"),
    (re.compile(r"mssql_query\(\)", re.I), "Microsoft SQL Server"),
    # Oracle
    (re.compile(r"ora-[0-9]{4,5}", re.I), "Oracle"),
    (re.compile(r"oracle error", re.I), "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    # Genéricos / ODBC
    (re.compile(r"odbc driver.*error", re.I), "ODBC Generic"),
    (re.compile(r"syntax error in string in query expression", re.I), "MS Access"),
    (re.compile(r"sqlstate\[[a-zA-Z0-9]+\]", re.I), "SQLSTATE Standard")
]

ERROR_PAYLOADS = [
    "'",
    "''",
    "\"",
    "\"\"",
    "' OR '1'='1",
    "' OR 1=1-- -",
    "' UNION SELECT NULL-- -",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "1' ORDER BY 1-- -",
    "1' ORDER BY 100-- -"
]

BOOLEAN_PAIRS = [
    # (True payload, False payload, is_numeric)
    ("' AND '1'='1", "' AND '1'='2", False),
    ("' OR '1'='1", "' OR '1'='2", False),
    ("1 AND 1=1", "1 AND 1=2", True),
    ("1 OR 1=1", "1 OR 1=2", True)
]

TIME_PAYLOADS = [
    # (Payload, DB / Variante)
    ("' OR SLEEP(3)-- -", "MySQL / MariaDB"),
    ("1 AND SLEEP(3)-- -", "MySQL / MariaDB"),
    ("'; SELECT pg_sleep(3)--", "PostgreSQL"),
    ("1 AND (SELECT 1 FROM pg_sleep(3))--", "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL")
]


class SQLiScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def scan_endpoint(self, base_url, param, default_val='1'):
        """
        Ejecuta análisis completo de SQLi sobre un parámetro específico:
        1. Error-based
        2. Boolean-based Blind
        3. Time-based Blind
        """
        findings = []

        # Obtener baseline inicial
        try:
            t_start = time.perf_counter()
            baseline = self.session.get(base_url, params={param: 'gl_baseline_check'}, timeout=self.timeout)
            baseline_time = time.perf_counter() - t_start
            baseline_code = baseline.status_code
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
        except Exception:
            # Si el endpoint no responde al baseline, omitir
            return findings

        # 1. ERROR-BASED SQLi
        error_found = False
        for payload in ERROR_PAYLOADS:
            try:
                resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
                cuerpo = resp.text

                # Buscar firmas de error
                for pattern, db_name in SQL_ERROR_PATTERNS:
                    if pattern.search(cuerpo):
                        findings.append({
                            'technique': 'Error-Based',
                            'severity': 'critica',
                            'detalle': f"Error SQL ({db_name}) confirmado al inyectar '{payload}' en parámetro '{param}'",
                            'evidence': pattern.pattern,
                            'url': base_url,
                            'cwe': 'CWE-89'
                        })
                        error_found = True
                        break

                if error_found:
                    break

                # Comprobar si provoca error 500 mientras baseline era 200
                if resp.status_code == 500 and baseline_code != 500:
                    findings.append({
                        'technique': 'Error-Based (Anomalía 500)',
                        'severity': 'media',
                        'detalle': f"Error HTTP 500 provocado únicamente con payload SQL '{payload}' en parámetro '{param}'",
                        'evidence': f"Status {resp.status_code} vs baseline {baseline_code}",
                        'url': base_url,
                        'cwe': 'CWE-89'
                    })
                    break
            except Exception:
                continue

        # Si ya se confirmó error crítico, continuar con el siguiente parámetro
        if error_found:
            return findings

        # 2. BOOLEAN-BASED BLIND SQLi
        for true_p, false_p, is_num in BOOLEAN_PAIRS:
            try:
                resp_true = self.session.get(base_url, params={param: true_p}, timeout=self.timeout)
                resp_false = self.session.get(base_url, params={param: false_p}, timeout=self.timeout)

                # Comparar longitudes y similitudes
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)

                # Si True responde 200 y False 500 / 404 / contenido muy diferente
                status_divergence = (resp_true.status_code == 200 and resp_false.status_code != 200)
                length_delta = abs(len_true - len_false)

                # Diferencia notable de tamaño (> 10% y al menos 40 bytes)
                size_divergence = length_delta > 40 and (length_delta / max(len_true, len_false, 1)) > 0.10

                if status_divergence or size_divergence:
                    # Confirmación: re-verificar con True para descartar contenido dinámico aleatorio
                    resp_confirm = self.session.get(base_url, params={param: true_p}, timeout=self.timeout)
                    if abs(len(resp_confirm.text) - len_true) < 20:
                        findings.append({
                            'technique': 'Boolean-Based Blind',
                            'severity': 'critica',
                            'detalle': f"Diferencia booleana detectada en parámetro '{param}' (True: {len_true} bytes, False: {len_false} bytes)",
                            'evidence': f"True: {true_p} | False: {false_p}",
                            'url': base_url,
                            'cwe': 'CWE-89'
                        })
                        break
            except Exception:
                continue

        # 3. TIME-BASED BLIND SQLi
        sleep_sec = 3
        for time_p, db_engine in TIME_PAYLOADS:
            try:
                t0 = time.perf_counter()
                self.session.get(base_url, params={param: time_p}, timeout=self.timeout + sleep_sec + 2)
                elapsed = time.perf_counter() - t0

                # Si el tiempo supera baseline + 2.5s (umbral de tolerancia)
                if elapsed >= (baseline_time + 2.5):
                    # Control: comprobar una petición no retardada inmediatamente
                    t_ctrl0 = time.perf_counter()
                    self.session.get(base_url, params={param: 'gl_ctrl_test'}, timeout=self.timeout)
                    elapsed_ctrl = time.perf_counter() - t_ctrl0

                    if elapsed_ctrl < 2.0:
                        # Re-confirmación del sleep para asegurar que no fue lag puntual
                        t1 = time.perf_counter()
                        self.session.get(base_url, params={param: time_p}, timeout=self.timeout + sleep_sec + 2)
                        elapsed_confirm = time.perf_counter() - t1

                        if elapsed_confirm >= (baseline_time + 2.5):
                            findings.append({
                                'technique': 'Time-Based Blind',
                                'severity': 'critica',
                                'detalle': f"Retardo intencional confirmado ({elapsed:.2f}s vs baseline {baseline_time:.2f}s) con '{time_p}' en parámetro '{param}' ({db_engine})",
                                'evidence': f"Elapsed: {elapsed:.2f}s, Confirm: {elapsed_confirm:.2f}s",
                                'url': base_url,
                                'cwe': 'CWE-89'
                            })
                            break
            except Exception:
                continue

        return findings
