# -*- coding: utf-8 -*-
"""
Command-line interface (CLI) entry point for GHOSTS LIGHTER.
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
        prog="ghosts-lighter",
        description=f"{PRODUCT_NAME} v{PRODUCT_VERSION} - Web Security Assessment Engine (DAST / OWASP Top 10)",
        epilog="Usage examples:\n"
               "  ghosts-lighter http://127.0.0.1:8080\n"
               "  ghosts-lighter -u http://127.0.0.1:8080 -f\n"
               "  ghosts-lighter http://127.0.0.1:8080 -a admin:password -w common.txt\n"
               "  ghosts-lighter http://127.0.0.1:8080 -a user1:pass1 --a2 user2:pass2 -o ctf_report.html\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # 1. Target Options
    g_target = parser.add_argument_group('Target Options')
    g_target.add_argument('target_url', nargs='?', default=None, help='Target URL (e.g., http://127.0.0.1:3000)')
    g_target.add_argument('-u', '-t', '--url', '--target', dest='url', default=None, help='Target URL via flag (e.g., -u http://127.0.0.1:8080)')
    g_target.add_argument('--local', action='store_true', help='Audit localhost (127.0.0.1)')
    g_target.add_argument('-p', '--port', type=int, default=80, help='Local port (default: 80)')
    g_target.add_argument('--http-port', type=int, default=80, help='Alternative HTTP port to verify HTTPS redirection')

    # 2. Authentication & Dual-Session (IDOR / BOLA)
    g_auth = parser.add_argument_group('Authentication & Dual-Session Options (IDOR / BOLA)')
    g_auth.add_argument('-a', '--auth', dest='auth', default=None, help='Session 1 credentials in user:password format (e.g., -a admin:admin)')
    g_auth.add_argument('-U', '--user', '--username', dest='username', default='admin', help='Session 1 username (default: admin)')
    g_auth.add_argument('-P', '--pass', '--password', dest='password', default='password', help='Session 1 password (default: password)')
    g_auth.add_argument('--a2', '--auth2', dest='auth2', default=None, help='Session 2 credentials in user:password format (e.g., --a2 user2:pass2)')
    g_auth.add_argument('--u2', '--user2', '--username2', dest='username2', default=None, help='Session 2 username for dual-session IDOR audit')
    g_auth.add_argument('--p2', '--pass2', '--password2', dest='password2', default=None, help='Session 2 password for dual-session IDOR audit')
    g_auth.add_argument('-l', '--login', '--login-path', dest='login_path', default='/login', help='Specific login form endpoint path (default: /login)')

    # 3. Crawler & Reconnaissance Options
    g_crawl = parser.add_argument_group('Crawler & Reconnaissance Options')
    g_crawl.add_argument('-w', '--wl', '--wordlist', dest='wl', default=None, help='Wordlist for Path Scan (resolves in ./wordlists/ or direct path)')
    g_crawl.add_argument('-m', '--pages', '--max-pages', dest='max_pages', type=int, default=40, help='Maximum pages to crawl (default: 40)')
    g_crawl.add_argument('-d', '--depth', '--max-depth', dest='max_depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    g_crawl.add_argument('-f', '--fast', dest='fast', action='store_true', help='Fast mode / CTF preset: activates --no-browser, --max-pages 15, --wl quickhits.txt')
    g_crawl.add_argument('--no-browser', '--no-selenium', dest='no_selenium', action='store_true', help='Disable dynamic headless rendering via Playwright')

    # 4. Reporting & Output Options
    g_out = parser.add_argument_group('Reporting & Output Options')
    g_out.add_argument('-o', '--out', '--output', dest='output', default=None, help='Path or filename for generated report (.html, .json, .sarif)')
    g_out.add_argument('--no-html', dest='no_html', action='store_true', help='Do not generate HTML report on disk')
    g_out.add_argument('-v', '--version', action='version', version=f"{PRODUCT_NAME} v{PRODUCT_VERSION}")

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

    # Process quick credentials shortcuts: -a user:pass and --a2 user2:pass2
    if args.auth:
        if ':' in args.auth:
            args.username, args.password = args.auth.split(':', 1)
        else:
            args.username = args.auth

    if args.auth2:
        if ':' in args.auth2:
            args.username2, args.password2 = args.auth2.split(':', 1)
        else:
            args.username2 = args.auth2

    # Process fast / CTF preset (-f / --fast)
    if args.fast:
        args.no_selenium = True
        if args.max_pages == 40:
            args.max_pages = 15
        if args.wl is None:
            args.wl = 'quickhits.txt'

    # Resolve target URL
    if args.local:
        target = f"http://127.0.0.1:{args.port}"
    elif args.url:
        target = args.url
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
            wordlist_path=args.wl,
            username2=args.username2,
            password2=args.password2
        )
        auditor.run_audit(generar_html=not args.no_html, output_path=args.output)
    except KeyboardInterrupt:
        print(f"\n{ICON_WARN} Audit interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"{ICON_FAIL} Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
