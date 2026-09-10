#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghosts Lighter Assessment Engine v1.0.0
Open Source Edition

Author: v1p3rx
License: MIT
"""

import sys
import os

# Asegurar que el paquete sea importable desde el directorio actual
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghosts_lighter import (
    PRODUCT_NAME,
    PRODUCT_VERSION,
    BANNER,
    ResultObject,
    LoginDiscoveryEngine,
    AuthSession,
    Crawler,
    BROWSER_AVAILABLE,
    ReporterEngine,
    _get_report_dir,
    AuditoriaMejorada,
    main
)

if __name__ == '__main__':
    main()
