# -*- coding: utf-8 -*-
"""
Authentication form discovery and classification engine.
"""


class LoginDiscoveryEngine:
    @staticmethod
    def classify_login_result(auth_ok, auth_msg, forms_found=True):
        if auth_ok:
            return ('PASS', f"Login form found and authentication successful: {auth_msg}")
        if not forms_found:
            return ('INFO', "NOT TESTED: Application does not expose a traditional HTML form (possible SPA or API auth).")
        if 'No recognizable login form' in str(auth_msg) or 'No se encontr' in str(auth_msg):
            return ('INFO', f"NOT TESTED: Could not automatically identify an authentication form. {auth_msg}")
        spa_keywords = ['SPA', 'React', 'Vue', 'Angular', 'javascript', 'client-side']
        if any(k in str(auth_msg) for k in spa_keywords) or any(k in str(auth_msg) for k in ('JS', 'bundle')):
            return ('INFO', "SPA detected. Traditional HTML login detection skipped.")
        if '401' in str(auth_msg) or '403' in str(auth_msg) or 'denied' in str(auth_msg).lower() or 'rechazad' in str(auth_msg).lower():
            return ('WARN', f"Login form found but credentials were rejected: {auth_msg}")
        return ('FAIL', auth_msg)
