# -*- coding: utf-8 -*-
"""
Authenticated session management and credential dispatch.
"""

from urllib.parse import urljoin
from ghosts_lighter.config import DEFAULT_TIMEOUT, WORDLISTS


class AuthSession:
    def __init__(self, session, base_url, username, password, login_path):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.login_path = login_path

    def _find_login_form(self, crawler_forms):
        user_hints = WORDLISTS['login_field_hints']['user']
        pass_hints = WORDLISTS['login_field_hints']['pass']
        for form in crawler_forms:
            names = [f['name'].lower() for f in form['fields']]
            has_user = any(any(h in n for h in user_hints) for n in names)
            has_pass = any(f['type'] == 'password' or any(h in f['name'].lower() for h in pass_hints) for f in form['fields'])
            if has_user and has_pass:
                return form
        return None

    def attempt_login(self, crawler_forms):
        if not self.username or not self.password:
            return (False, "No credentials provided (--username/--password)")
        target_form = None
        if self.login_path:
            try:
                from ghosts_lighter.crawler.spider import Crawler
                url = urljoin(self.base_url + '/', self.login_path.lstrip('/'))
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
                extra_crawler = Crawler(self.session, url, max_pages=1, max_depth=0, use_selenium=False)
                target_form = self._find_login_form(extra_crawler._extract_forms(resp.text, url))
            except Exception:
                target_form = None

        if target_form is None:
            target_form = self._find_login_form(crawler_forms)

        if target_form is None:
            return (False, "No recognizable login form found")

        user_hints = WORDLISTS['login_field_hints']['user']
        pass_hints = WORDLISTS['login_field_hints']['pass']
        payload = {}
        for field in target_form['fields']:
            n = field['name']
            nl = n.lower()
            if any(h in nl for h in user_hints):
                payload[n] = self.username
            elif field['type'] == 'password' or any(h in nl for h in pass_hints):
                payload[n] = self.password
            elif field['type'] not in ('submit', 'button'):
                payload[n] = ''

        try:
            if target_form['method'] == 'GET':
                resp = self.session.get(target_form['action'], params=payload, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            else:
                resp = self.session.post(target_form['action'], data=payload, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code < 400:
                return (True, f"Login submitted to {target_form['action']} ({resp.status_code})")
            else:
                return (False, f"Server responded with {resp.status_code} during login attempt")
        except Exception as e:
            return (False, f"Error submitting login: {e}")
