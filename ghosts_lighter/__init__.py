# -*- coding: utf-8 -*-
"""
GHOSTS LIGHTER - Assessment Engine
Local · Fast · Actionable · Open Source (OWASP Top 10)
"""

from .config import PRODUCT_NAME, PRODUCT_VERSION, BANNER
from .core.models import ResultObject
from .auth.detector import LoginDiscoveryEngine
from .auth.session_auth import AuthSession
from .crawler.spider import Crawler, BROWSER_AVAILABLE
from .reporters.engine import ReporterEngine, _get_report_dir
from .scanners.manager import AuditoriaMejorada, SecurityAuditEngine, EnhancedAudit
from .cli import main

__version__ = PRODUCT_VERSION
__author__ = "v1p3rx"
__license__ = "MIT"

__all__ = [
    'PRODUCT_NAME',
    'PRODUCT_VERSION',
    'BANNER',
    'ResultObject',
    'LoginDiscoveryEngine',
    'AuthSession',
    'Crawler',
    'BROWSER_AVAILABLE',
    'ReporterEngine',
    '_get_report_dir',
    'AuditoriaMejorada',
    'SecurityAuditEngine',
    'EnhancedAudit',
    'main'
]
