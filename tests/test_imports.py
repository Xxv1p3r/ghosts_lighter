# -*- coding: utf-8 -*-
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ghosts_lighter
from ghosts_lighter.config import BANNER, WORDLISTS, TEST_METADATA, STATUS_META
from ghosts_lighter.core.models import ResultObject
from ghosts_lighter.auth.detector import LoginDiscoveryEngine
from ghosts_lighter.auth.session_auth import AuthSession
from ghosts_lighter.crawler.spider import Crawler
from ghosts_lighter.reporters.engine import ReporterEngine, _get_report_dir
from ghosts_lighter.scanners.manager import AuditoriaMejorada
from ghosts_lighter.cli import build_parser


class TestImports(unittest.TestCase):
    def test_version_and_metadata(self):
        self.assertEqual(ghosts_lighter.__version__, '1.0.0')
        self.assertEqual(ghosts_lighter.__author__, 'v1p3rx')
        self.assertEqual(ghosts_lighter.__license__, 'MIT')

    def test_all_exports_available(self):
        self.assertTrue(hasattr(ghosts_lighter, 'ResultObject'))
        self.assertTrue(hasattr(ghosts_lighter, 'AuditoriaMejorada'))
        self.assertTrue(hasattr(ghosts_lighter, 'Crawler'))
        self.assertTrue(hasattr(ghosts_lighter, 'ReporterEngine'))
        self.assertTrue(hasattr(ghosts_lighter, 'LoginDiscoveryEngine'))
        self.assertTrue(hasattr(ghosts_lighter, 'AuthSession'))
        self.assertTrue(hasattr(ghosts_lighter, 'main'))

    def test_config_wordlists(self):
        self.assertIn('api_endpoints', WORDLISTS)
        self.assertIn('security_payloads', WORDLISTS)
        self.assertIn('dev_paths', WORDLISTS)
        self.assertGreater(len(WORDLISTS['dev_paths']), 10)

    def test_cli_parser(self):
        parser = build_parser()
        args = parser.parse_args(['http://localhost:3000', '--no-browser', '--max-pages', '10'])
        self.assertEqual(args.target_url, 'http://localhost:3000')
        self.assertTrue(args.no_selenium)
        self.assertEqual(args.max_pages, 10)


if __name__ == '__main__':
    unittest.main()
