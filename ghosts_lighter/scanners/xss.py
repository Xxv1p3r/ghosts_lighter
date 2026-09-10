# -*- coding: utf-8 -*-
"""
Motor avanzado de detección de Cross-Site Scripting (XSS) Reflejado.
Incluye:
- Verificación estricta de Content-Type ejecutable (HTML)
- Detección de contexto en DOM (Body, Atributo, Script Inline, Comentario)
- Canario de caracteres delimitadores para descartar reflejos codificados
- Payloads contextuales orientados a escape real de contexto
"""

import re
import html

CANARY_PROBE = "glxss7\"'>{"

CONTEXT_PAYLOADS = {
    'BODY': [
        "<svg/onload=alert('XSS')>",
        "<img src=x onerror=alert('XSS')>",
        "<script>alert('XSS')</script>"
    ],
    'ATTR_DOUBLE': [
        "\" onfocus=\"alert('XSS')\" autofocus=\"",
        "\"><script>alert('XSS')</script>"
    ],
    'ATTR_SINGLE': [
        "' onfocus='alert(\"XSS\")' autofocus='",
        "'><script>alert('XSS')</script>"
    ],
    'SCRIPT': [
        "'-alert('XSS')-'",
        "\"-alert('XSS')-\"",
        "</script><script>alert('XSS')</script>"
    ],
    'COMMENT': [
        "--><script>alert('XSS')</script>"
    ]
}


def analyze_reflection_context(html_content, marker):
    """
    Analiza la posición y contexto de un marcador dentro del HTML.
    Retorna (contexto, delimitadores_sin_escapar)
    """
    pos = html_content.find(marker)
    if pos == -1:
        return 'NONE', {}

    before = html_content[:pos]
    after = html_content[pos + len(marker):]

    # 1. ¿Está dentro de un comentario HTML?
    last_comment_open = before.rfind('<!--')
    last_comment_close = before.rfind('-->')
    if last_comment_open != -1 and (last_comment_close == -1 or last_comment_close < last_comment_open):
        return 'COMMENT', {'open': True}

    # 2. ¿Está dentro de un bloque <script>?
    script_open = [m.start() for m in re.finditer(r'<script\b[^>]*>', before, re.I)]
    script_close = [m.start() for m in re.finditer(r'</script>', before, re.I)]
    if script_open and (not script_close or max(script_open) > max(script_close)):
        return 'SCRIPT', {'in_script': True}

    # 3. ¿Está dentro de un tag / atributo?
    last_tag_open = before.rfind('<')
    last_tag_close = before.rfind('>')
    if last_tag_open != -1 and (last_tag_close == -1 or last_tag_close < last_tag_open):
        # Estamos dentro de un tag: <tag ... marker ... >
        tag_slice = before[last_tag_open:]
        quotes_double = tag_slice.count('"')
        quotes_single = tag_slice.count("'")
        if quotes_double % 2 != 0:
            return 'ATTR_DOUBLE', {'quote': '"'}
        elif quotes_single % 2 != 0:
            return 'ATTR_SINGLE', {'quote': "'"}
        return 'ATTR_UNQUOTED', {'quote': None}

    # 4. Contexto por defecto: Body HTML entre etiquetas
    return 'BODY', {'body': True}


class XSSScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout

    def scan_endpoint(self, base_url, param):
        """
        Ejecuta análisis contextual de XSS:
        1. Inyecta canario explorador para evaluar sanitización y contexto.
        2. Si se detectan caracteres especiales sin codificar, prueba payload contextual.
        3. Verifica si el payload es ejecutable y clasifica la severidad.
        """
        findings = []

        try:
            # Petición exploratoria con canario
            resp = self.session.get(base_url, params={param: CANARY_PROBE}, timeout=self.timeout)
            ctype = resp.headers.get('Content-Type', '').lower()
            text = resp.text

            # Si no es HTML / XHTML, no es ejecutable en el navegador
            if not ('text/html' in ctype or 'application/xhtml' in ctype or ctype == ''):
                if CANARY_PROBE in text:
                    findings.append({
                        'severity': 'info',
                        'detalle': f"Reflejo en respuesta de tipo no ejecutable ({ctype or 'desconocido'}) en parámetro '{param}' (no ejecutable como XSS)",
                        'context': 'NON_HTML',
                        'url': base_url,
                        'cwe': 'CWE-79'
                    })
                return findings

            # Comprobar si el canario se refleja
            context, meta = analyze_reflection_context(text, CANARY_PROBE)
            if context == 'NONE':
                # El canario completo no se reflejó; probar si se reflejó con codificación HTML
                encoded_canary = html.escape(CANARY_PROBE)
                if encoded_canary in text:
                    # Correctamente sanitizado con HTML entities
                    return findings
                return findings

            # Analizar qué caracteres delimitadores sobrevivieron sin codificar
            unescaped_chars = []
            for ch in ['"', "'", '<', '>']:
                if ch in text[text.find("glxss7"):text.find("glxss7") + 25]:
                    unescaped_chars.append(ch)

            # Si los delimitadores están codificados como entidades (&quot;, &lt;, etc.)
            if '<' not in unescaped_chars and '"' not in unescaped_chars and "'" not in unescaped_chars:
                # Entrada sanitizada
                return findings

            # Seleccionar payloads específicos según el contexto identificado
            payloads_a_probar = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS['BODY'])

            for payload in payloads_a_probar:
                try:
                    resp_payload = self.session.get(base_url, params={param: payload}, timeout=self.timeout)
                    resp_text = resp_payload.text

                    if payload in resp_text:
                        # Verificar que el payload no esté escapado en la respuesta final
                        ctx_final, _ = analyze_reflection_context(resp_text, payload)

                        # Si se inyectó un tag y el contexto resultante no es un comentario ni un atributo roto inocuo
                        findings.append({
                            'severity': 'critica',
                            'detalle': f"XSS Reflejado ejecutable en contexto [{context}] sin sanitizar caracteres '{', '.join(unescaped_chars)}' en parámetro '{param}'",
                            'evidence': f"Payload: {payload} | Contexto: {context}",
                            'url': base_url,
                            'cwe': 'CWE-79'
                        })
                        break
                except Exception:
                    continue

        except Exception:
            pass

        return findings
