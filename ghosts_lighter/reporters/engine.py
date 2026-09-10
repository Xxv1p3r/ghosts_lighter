# -*- coding: utf-8 -*-
"""
Motor de generación de reportes (JSON, SARIF, HTML, TXT).
"""

import os
import json
import datetime as dt
from ghosts_lighter.config import PRODUCT_VERSION

def _get_report_dir():
    target_dir = '/opt/ghosts-lighter/reporte'
    try:
        os.makedirs(target_dir, exist_ok=True)
        test_file = os.path.join(target_dir, '.write_test')
        with open(test_file, 'w') as f:
            f.write('1')
        os.remove(test_file)
        return target_dir
    except (OSError, PermissionError):
        cwd_dir = os.path.join(os.getcwd(), 'reporte')
        os.makedirs(cwd_dir, exist_ok=True)
        return cwd_dir


class ReporterEngine:
    def __init__(self, result, target_url, hostname):
        self.result = result
        self.target_url = target_url
        self.hostname = hostname
        self.now = dt.datetime.now()
        self.report_dir = _get_report_dir()

    def generate_json(self, output_path=None):
        summary = self.result.get_summary()
        data = {
            'target': self.target_url,
            'hostname': self.hostname,
            'timestamp': self.now.isoformat(),
            'version': PRODUCT_VERSION,
            'summary': {
                'total': summary['total'],
                'passed': summary['passed'],
                'warns': summary['warns'],
                'failed': summary['failed'],
                'skipped': summary['skipped'],
                'executed': summary['executed'],
                'score': summary['score']
            },
            'results': self.result.results,
            'messages': self.result.messages,
            'findings': self.result.findings,
            'crawl_data': {
                'visited_urls': self.result.crawl_data.get('visited', []),
                'forms': self.result.crawl_data.get('forms', []),
                'js_endpoints': self.result.crawl_data.get('js_endpoints', []),
                'js_secrets': self.result.crawl_data.get('js_secrets', []),
                'bundles_analizados': self.result.crawl_data.get('js_bundles_analizados', 0)
            },
            'auth_status': self.result.auth_status,
            'tech_stack': self.result.tech_stack,
            'api_endpoints': self.result.api_endpoints
        }
        if output_path is None:
            timestamp = self.now.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.report_dir, f'informe_ghosts_lighter_{timestamp}.json')
        elif not os.path.isabs(output_path):
            output_path = os.path.join(self.report_dir, output_path)

        if not output_path.endswith('.json'):
            output_path = output_path.rsplit('.', 1)[0] + '.json'

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return os.path.abspath(output_path)

    def generate_sarif(self, output_path=None):
        severity_map = {
            'critica': 'error',
            'alta': 'error',
            'media': 'warning',
            'baja': 'note',
            'info': 'note'
        }
        sarif_results = []
        for finding in self.result.findings:
            sarif_results.append({
                'ruleId': finding.get('test', 'General'),
                'level': severity_map.get(finding.get('severidad', 'info'), 'note'),
                'message': {
                    'text': finding.get('detalle', finding.get('description', ''))
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': finding.get('url', finding.get('endpoint')) or self.target_url
                        }
                    }
                }]
            })

        sarif = {
            '$schema': 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'GHOSTS LIGHTER',
                        'version': PRODUCT_VERSION,
                        'informationUri': 'https://github.com/v1p3rx/ghosts-lighter',
                        'rules': []
                    }
                },
                'results': sarif_results
            }]
        }

        if output_path is None:
            timestamp = self.now.strftime('%Y%m%d_%H%M%S')
            output_path = os.path.join(self.report_dir, f'informe_ghosts_lighter_{timestamp}.sarif')
        elif not os.path.isabs(output_path):
            output_path = os.path.join(self.report_dir, output_path)

        if not output_path.endswith('.sarif'):
            output_path = output_path.rsplit('.', 1)[0] + '.sarif'

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

        return os.path.abspath(output_path)

    def generate_html(self, output_path=None):
        if hasattr(self, '_legacy_generate_html'):
            return self._legacy_generate_html(output_path)
        print("   HTML: Usando generador estándar.")
        return None

    def generate_all(self, output_prefix=None):
        timestamp = self.now.strftime('%Y%m%d_%H%M%S')
        prefix = output_prefix if output_prefix else f'informe_ghosts_lighter_{timestamp}'
        results = {}
        html_path = self.generate_html(f"{prefix}.html")
        if html_path:
            results['html'] = html_path
        json_path = self.generate_json(f"{prefix}.json")
        if json_path:
            results['json'] = json_path
        sarif_path = self.generate_sarif(f"{prefix}.sarif")
        if sarif_path:
            results['sarif'] = sarif_path
        return results

