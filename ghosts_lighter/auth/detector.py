# -*- coding: utf-8 -*-
"""
Motor de descubrimiento y clasificación de formularios de autenticación.
"""


class LoginDiscoveryEngine:
    @staticmethod
    def classify_login_result(auth_ok, auth_msg, forms_found=True):
        if auth_ok:
            return ('PASS', f"Formulario encontrado y autenticación exitosa: {auth_msg}")
        if not forms_found:
            return ('INFO', "NOT TESTED: La aplicación no expone un formulario HTML tradicional (posible SPA o autenticación API).")
        if 'No se encontró un formulario reconocible' in str(auth_msg):
            return ('INFO', f"NOT TESTED: No fue posible identificar automáticamente un formulario de autenticación. {auth_msg}")
        spa_keywords = ['SPA', 'React', 'Vue', 'Angular', 'javascript', 'client-side']
        if any(k in str(auth_msg) for k in spa_keywords) or any(k in str(auth_msg) for k in ('JS', 'bundle')):
            return ('INFO', "SPA detectada. Se omitió la detección clásica de login.")
        if '401' in str(auth_msg) or '403' in str(auth_msg) or 'denied' in str(auth_msg).lower():
            return ('WARN', f"Formulario encontrado pero las credenciales fueron rechazadas: {auth_msg}")
        return ('FAIL', auth_msg)
