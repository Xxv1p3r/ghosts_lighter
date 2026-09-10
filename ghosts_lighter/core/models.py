# -*- coding: utf-8 -*-
"""
Modelos de datos y contenedores de resultados de auditoría.
"""

import datetime as dt


class ResultObject:
    def __init__(self, target_url=""):
        self.target_url = target_url
        self.results = {}
        self.messages = {}
        self.findings = []
        self.crawl_data = {}
        self.auth_status = {}
        self.tech_stack = []
        self.api_endpoints = []

    def add_result(self, test_name, status, message=""):
        self.results[test_name] = status
        if message:
            self.messages[test_name] = message

    def add_finding(self, test_name, severity="media", detalle="", url="", cwe=""):
        self.findings.append({
            "test": test_name,
            "type": test_name,
            "description": detalle,
            "severity": severity,
            "severidad": severity,
            "detalle": detalle,
            "evidence": detalle,
            "url": url,
            "endpoint": url,
            "cwe": cwe
        })

    def get_summary(self):
        total = len(self.results)
        passed = sum(1 for v in self.results.values() if v == 'PASS')
        warns = sum(1 for v in self.results.values() if v == 'WARN')
        failed = sum(1 for v in self.results.values() if v == 'FAIL')
        skipped = sum(1 for v in self.results.values() if v == 'SKIP')
        executed = total - skipped
        score = ((passed + warns) / executed * 100) if executed > 0 else 0.0
        return {
            'total': total,
            'passed': passed,
            'warns': warns,
            'failed': failed,
            'skipped': skipped,
            'executed': executed,
            'score': round(score, 1)
        }

    def to_dict(self):
        return {
            'target': getattr(self, 'target_url', ''),
            'timestamp': dt.datetime.now().isoformat(),
            'summary': self.get_summary(),
            'results': self.results,
            'messages': self.messages,
            'findings': self.findings,
            'crawl_data': self.crawl_data,
            'auth_status': self.auth_status,
            'tech_stack': self.tech_stack,
            'api_endpoints': self.api_endpoints
        }
