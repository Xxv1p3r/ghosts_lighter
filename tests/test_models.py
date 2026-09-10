# -*- coding: utf-8 -*-
import unittest
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ghosts_lighter.core.models import ResultObject
from ghosts_lighter.reporters.engine import ReporterEngine


class TestModelsAndReporter(unittest.TestCase):
    def test_result_object_summary(self):
        res = ResultObject("http://127.0.0.1:8080")
        res.add_result("Test 1", "PASS", "Todo bien")
        res.add_result("Test 2", "WARN", "Alerta leve")
        res.add_result("Test 3", "FAIL", "Falla detectada")
        res.add_result("Test 4", "SKIP", "Omitido")

        summary = res.get_summary()
        self.assertEqual(summary['total'], 4)
        self.assertEqual(summary['passed'], 1)
        self.assertEqual(summary['warns'], 1)
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['skipped'], 1)
        self.assertEqual(summary['executed'], 3)
        # Score = (passed + warns) / executed * 100 = 2 / 3 * 100 = 66.7
        self.assertAlmostEqual(summary['score'], 66.7, places=1)

    def test_findings_addition(self):
        res = ResultObject("http://127.0.0.1:8080")
        res.add_finding("SQLi", severity="critica", detalle="Error syntax", url="http://127.0.0.1/sqli", cwe="CWE-89")
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0]['severity'], 'critica')
        self.assertEqual(res.findings[0]['cwe'], 'CWE-89')

    def test_sarif_generation(self):
        res = ResultObject("http://127.0.0.1:8080")
        res.add_finding("Inyeccion SQL (SQLi)", severity="critica", detalle="Firma SQL detectada", url="http://127.0.0.1/item?id=1")
        reporter = ReporterEngine(res, "http://127.0.0.1:8080", "127.0.0.1")
        sarif_file = reporter.generate_sarif()
        self.assertTrue(os.path.exists(sarif_file))

        with open(sarif_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data['version'], '2.1.0')
        self.assertEqual(len(data['runs'][0]['results']), 1)
        self.assertEqual(data['runs'][0]['results'][0]['level'], 'error')

        # Limpieza
        try:
            os.remove(sarif_file)
        except Exception:
            pass


if __name__ == '__main__':
    unittest.main()
