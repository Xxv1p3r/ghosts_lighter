# -*- coding: utf-8 -*-
"""
Punto de entrada de línea de comandos (CLI) para GHOSTS LIGHTER.
"""

import sys
import argparse
import warnings

from ghosts_lighter.config import (
    BANNER,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    ICON_WARN,
    ICON_FAIL
)
from ghosts_lighter.scanners.manager import AuditoriaMejorada


def build_parser():
    parser = argparse.ArgumentParser(
        description=f"{PRODUCT_NAME} v{PRODUCT_VERSION} - Escaner de Seguridad Web con descubrimiento real",
        epilog="Ejemplo: ghosts-lighter http://127.0.0.1:3000 --username admin --password admin"
    )

    parser.add_argument('target_url', nargs='?', default=None, help='URL objetivo (ej: http://127.0.0.1:3000)')
    parser.add_argument('--local', action='store_true', help='Usar 127.0.0.1')
    parser.add_argument('--port', type=int, default=80, help='Puerto local')
    parser.add_argument('--http-port', type=int, default=80, help='Puerto HTTP alternativo')
    parser.add_argument('--username', default='admin', help='Usuario para autenticacion (default: admin)')
    parser.add_argument('--password', default='password', help='Contrasena para autenticacion (default: password)')
    parser.add_argument('--login-path', default='/dvwa/login.php', help='Ruta especifica del formulario de login, ej: /login')
    parser.add_argument('--max-pages', type=int, default=40, help='Maximo de paginas a crawlear (default 40)')
    parser.add_argument('--max-depth', type=int, default=2, help='Profundidad maxima del crawler (default 2)')
    parser.add_argument(
        '--no-browser', '--no-selenium',
        dest='no_selenium',
        action='store_true',
        help='Desactiva el renderizado con navegador headless (Playwright) / SPA discovery'
    )
    parser.add_argument(
        '--wl', '--wordlist',
        dest='wl',
        default=None,
        help='Wordlist personalizada para el Path Scan. Nombre simple se resuelve contra ./wordlists/. Ej: --wl common.txt'
    )
    parser.add_argument('-o', '--output', default=None, help='Archivo o nombre de salida para el reporte')
    parser.add_argument('--version', action='version', version=f"{PRODUCT_NAME} v{PRODUCT_VERSION}")
    return parser


def main(argv=None):
    warnings.filterwarnings('ignore')
    print(BANNER)

    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args(argv)

    if args.local:
        target = f"http://127.0.0.1:{args.port}"
    elif args.target_url:
        target = args.target_url
    else:
        parser.print_help()
        sys.exit(1)

    try:
        auditor = AuditoriaMejorada(
            target_url=target,
            http_port=args.http_port,
            username=args.username,
            password=args.password,
            login_path=args.login_path,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            no_selenium=args.no_selenium,
            wordlist_path=args.wl
        )
        auditor.run_audit(generar_html=True, output_path=args.output)
    except KeyboardInterrupt:
        print(f"\n{ICON_WARN} Auditoria interrumpida")
        sys.exit(130)
    except Exception as e:
        print(f"{ICON_FAIL} Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
