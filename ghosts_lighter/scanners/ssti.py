# -*- coding: utf-8 -*-
"""
Motor de detección de Server-Side Template Injection (SSTI).

Enfoque:
- Pruebas poliglotas de evaluación de expresiones con operandos aleatorios.
  No se busca el payload reflejado, sino el *resultado aritmético* de la
  expresión, que es un número de 5-6 dígitos imposible de confundir con el
  propio payload ni con contenido estático de la página.
- Confirmación determinista: ante un posible acierto se repite la petición y
  se exige el mismo resultado antes de reportar.
- Fingerprinting del motor (Jinja2 vs Twig) mediante la semántica de
  `{{n*'s'}}`, que concatena en Jinja2 y multiplica en Twig.

El payload se elimina de la respuesta (crudo y URL-encoded) antes de buscar el
resultado, de modo que un endpoint que solo refleja la entrada nunca genere un
hallazgo.
"""

import re
import random
from urllib.parse import quote, quote_plus

# Parámetros donde suele aterrizar entrada de usuario renderizada en plantillas
SSTI_PARAM_HINTS = {
    'q', 'query', 'search', 's', 'keyword', 'term', 'id', 'user', 'username',
    'name', 'message', 'msg', 'comment', 'content', 'text', 'input', 'value',
    'data', 'title', 'subject', 'email', 'mail', 'lang', 'language', 'locale',
    'theme', 'template', 'page', 'view', 'format', 'callback', 'filter',
    'category', 'tag', 'description', 'body', 'note', 'label', 'field',
    'code', 'expression', 'expr', 'custom', 'snippet', 'render'
}

# (plantilla con los marcadores A y B sustituidos por operandos aleatorios)
SSTI_PAYLOADS = [
    ("{{A*B}}", "Jinja2 / Twig / Nunjucks"),
    ("${A*B}", "Freemarker / JSP EL / Thymeleaf"),
    ("#{A*B}", "Ruby (ERB) / Groovy"),
    ("<%= A*B %>", "ERB / EJS"),
    ("{A*B}", "Smarty"),
    ("${{A*B}}", "Motor dollar-doble-llave"),
    ("@(A*B)", "Razor (.NET)"),
]


class SSTIScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    @staticmethod
    def _limpiar_reflejo(texto, payload):
        """Elimina el payload reflejado (crudo y URL-encoded) antes de buscar el resultado."""
        limpio = texto.replace(payload, '')
        for variante in (quote(payload, safe=''), quote_plus(payload, safe='')):
            if variante and variante != payload:
                limpio = limpio.replace(variante, '')
        return limpio

    @staticmethod
    def _resultado_presente(texto, resultado):
        # Se exige que el numero no sea parte de otro numero mayor
        return re.search(rf"(?<!\d){re.escape(str(resultado))}(?!\d)", texto) is not None

    @staticmethod
    def _operandos():
        return random.randint(101, 999), random.randint(101, 999)

    @staticmethod
    def _construir_payload(plantilla, a, b):
        return plantilla.replace('A', str(a)).replace('B', str(b))

    def _identificar_motor(self, base_url, param):
        """
        Distingue Jinja2 (concatena cadenas) de Twig (multiplica numeros).
        Retorna la etiqueta del motor o None si no se puede determinar.
        """
        a = random.randint(2, 4)
        b = random.randint(12, 19)
        payload = f"{{{{{a}*'{b}'}}}}"
        try:
            resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
        except Exception:
            return None
        cuerpo = self._limpiar_reflejo(resp.text or '', payload)
        if self._resultado_presente(cuerpo, str(b) * a):
            return "Jinja2 (Python)"
        if self._resultado_presente(cuerpo, str(a * b)):
            return "Twig (PHP)"
        return None

    def scan_endpoint(self, base_url, param):
        """
        Ejecuta análisis de SSTI sobre un parámetro:
        1. Baseline para descartar coincidencias espurias del resultado.
        2. Pruebas poliglotas con operandos aleatorios.
        3. Confirmación determinista + fingerprint del motor.
        """
        findings = []

        try:
            baseline = self.session.get(base_url, params={param: f"glssti{random.randint(1000, 9999)}"}, timeout=self.timeout)
            baseline_text = baseline.text or ''
        except Exception:
            return findings

        a, b = self._operandos()
        producto = a * b
        # Si el número ya aparece sin inyectar, el par no sirve como prueba
        if self._resultado_presente(baseline_text, producto):
            return findings

        for plantilla, motor in SSTI_PAYLOADS:
            payload = self._construir_payload(plantilla, a, b)
            try:
                resp = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
            except Exception:
                continue
            cuerpo = self._limpiar_reflejo(resp.text or '', payload)
            if not self._resultado_presente(cuerpo, producto):
                continue

            # Confirmación determinista: repetir y exigir el mismo resultado
            try:
                resp2 = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
            except Exception:
                continue
            cuerpo2 = self._limpiar_reflejo(resp2.text or '', payload)
            if not self._resultado_presente(cuerpo2, producto):
                continue

            motor_detectado = self._identificar_motor(base_url, param) or motor
            findings.append({
                'technique': motor_detectado,
                'severity': 'critica',
                'detalle': f"Template Injection confirmada en parametro '{param}': la expresion '{payload}' fue evaluada a {producto} (motor probable: {motor_detectado}) - potencial ejecucion remota de codigo",
                'evidence': f"Payload: {payload} | Resultado evaluado: {producto}",
                'url': base_url,
                'cwe': 'CWE-1336'
            })
            break

        return findings
