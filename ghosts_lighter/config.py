# -*- coding: utf-8 -*-
"""
Configuración, constantes, wordlists y metadatos de GHOSTS LIGHTER.
"""

import sys
import re
import os
import warnings
from pathlib import Path

# Directorio raíz del proyecto
REPO_ROOT = Path(__file__).resolve().parent.parent
WORDLISTS_DIR = REPO_ROOT / 'wordlists'

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ANSI_VERDE = '[1;32m'
ANSI_ROJO = '[1;31m'
ANSI_AMARILLO = '[1;33m'
ANSI_BLANCO = '[1;37m'
ANSI_GRIS = '[0;37m'
ANSI_CYAN = '[1;36m'
ANSI_MAGENTA = '[1;35m'
ANSI_RESET = '[0m'

ICON_PASS = '[+] '
ICON_FAIL = '[-] '
ICON_WARN = '[!] '
ICON_SKIP = '[?] '
ICON_INFO = '[*] '
ICON_MASTER = '[M] '
ICON_DETECT = '[D] '
ICON_API = '[A] '
ICON_AUTH = '[L] '
ICON_DEP = '[P] '
ICON_CRAWL = '[C] '

warnings.filterwarnings('ignore')

DEFAULT_TIMEOUT = 8
ASSET_TIMEOUT = 4
PRODUCT_NAME = 'GHOSTS LIGHTER'
PRODUCT_VERSION = '1.0.0'

BANNER = """
  ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓  ██████ 
 ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▒██    ▒ 
▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░░ ▓██▄   
░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░   ▒   ██▒
░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ▒██████▒▒
 ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ▒ ▒▓▒ ▒ ░
  ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    ░ ░▒  ░ ░
░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      ░  ░  ░  
      ░  ░  ░  ░    ░ ░        ░                 ░  

       L I G H T E R  ·  Assessment Engine

LOCAL · FAST · ACTIONABLE · OPEN SOURCE
"""

JS_PATTERNS = {
    'api_endpoints': re.compile(r"""
    ["']
    (
        /
        (?:
            api(?:/v\d+)? |
            rest(?:/v\d+)? |
            v\d+ |
            graphql |
            gql |
            auth |
            oauth |
            login |
            logout |
            session |
            token |
            users? |
            accounts? |
            profiles? |
            products? |
            orders? |
            payments? |
            billing |
            admin |
            dashboard |
            search |
            query |
            upload |
            files? |
            download |
            webhooks? |
            health |
            metrics
        )
        [a-zA-Z0-9_./?=&%:@+\-]*
    )
    ["']
    """, re.I | re.X),
    'secrets': re.compile(r"""(api[_-]?key|auth[_-]?token|bearer|secret)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{16,})["']""", re.I)
}

MAX_JS_BUNDLE_BYTES = 2097152
MAX_JS_BUNDLES = 40

# Secretos HMAC habituales en JWT. Si alguno valida la firma de un token, el
# hallazgo es una prueba criptografica (no una heuristica).
JWT_WEAK_SECRETS = [
    'secret', 'secretkey', 'secret_key', 'secret-key', 'mysecret', 'my_secret',
    'supersecret', 'super_secret', 'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret',
    'token', 'tokenkey', 'token_key', 'password', 'password123', 'passw0rd',
    'changeme', 'change-me', 'admin', 'administrator', 'default', 'test',
    'testing', 'dev', 'development', 'production', 'staging', 'demo',
    'example', 'sample', 'key', 'privatekey', 'private_key', 'apikey',
    'api_key', 'auth', 'authentication', 'authkey', 'hmac', 'hmackey',
    'signature', 'signingkey', 's3cr3t', '123456', '12345678', '1234567890',
    'qwerty', 'letmein', 'welcome', 'root', 'toor', 'abc123',
    'your-256-bit-secret', 'your-secret-key', 'topsecret', 'top_secret',
    'blahblah', 'iloveyou', 'monkey', 'dragon', 'master', 'sunshine',
]
WORDLISTS = {   'api_endpoints': [   '/api',
                         '/api/v1',
                         '/api/v2',
                         '/api/v3',
                         '/rest',
                         '/rest/v1',
                         '/graphql',
                         '/gql',
                         '/query',
                         '/graphiql',
                         '/playground',
                         '/swagger',
                         '/swagger.json',
                         '/swagger/v1/swagger.json',
                         '/openapi',
                         '/openapi.json',
                         '/openapi.yaml',
                         '/openapi.yml',
                         '/docs',
                         '/documentation',
                         '/redoc',
                         '/rapidoc',
                         '/auth',
                         '/login',
                         '/logout',
                         '/signup',
                         '/register',
                         '/users',
                         '/user',
                         '/profile',
                         '/account',
                         '/me',
                         '/products',
                         '/product',
                         '/items',
                         '/orders',
                         '/cart',
                         '/search',
                         '/query',
                         '/filter',
                         '/find',
                         '/upload',
                         '/files',
                         '/media',
                         '/download',
                         '/admin',
                         '/admin/api',
                         '/administrator',
                         '/dashboard',
                         '/metrics',
                         '/health',
                         '/healthz',
                         '/ready',
                         '/live'],
    'common_vuln_paths': [   '/vulnerabilities/sqli/',
                             '/vulnerabilities/sqli_blind/',
                             '/vulnerabilities/xss_r/',
                             '/vulnerabilities/xss_s/',
                             '/vulnerabilities/csrf/',
                             '/vulnerabilities/fi/?page=include.php',
                             '/vulnerabilities/upload/',
                             '/vulnerabilities/brute/'],
    'default_credentials': {   'passwords': [   'password',
                                                'admin',
                                                '123456',
                                                '12345678',
                                                'root',
                                                'toor',
                                                'pass',
                                                'default',
                                                'admin123',
                                                'password123',
                                                'changeme',
                                                'secret',
                                                'welcome',
                                                '12345',
                                                'tomcat',
                                                'jenkins',
                                                'postgres',
                                                'mysql',
                                                'oracle',
                                                'raspberry',
                                                'dev123',
                                                'test123',
                                                '1234',
                                                'qwerty',
                                                'letmein'],
                               'users': [   'admin',
                                            'root',
                                            'administrator',
                                            'webmin',
                                            'user',
                                            'guest',
                                            'test',
                                            'sysadmin',
                                            'super',
                                            'supervisor',
                                            'manager',
                                            'operator',
                                            'support',
                                            'tomcat',
                                            'jenkins',
                                            'postgres',
                                            'mysql',
                                            'oracle',
                                            'ubuntu',
                                            'pi',
                                            'developer',
                                            'dev',
                                            'api',
                                            'service',
                                            'testuser']},
    'dev_paths': [   '/.env',
                     '/.env.local',
                     '/.env.development',
                     '/.env.production',
                     '/.git/HEAD',
                     '/.git/config',
                     '/.gitignore',
                     '/.gitattributes',
                     '/.svn/entries',
                     '/.svn/wc.db',
                     '/.hg/hgrc',
                     '/.htaccess',
                     '/.htpasswd',
                     '/.htgroup',
                     '/config.php',
                     '/wp-config.php',
                     '/wp-config-sample.php',
                     '/settings.py',
                     '/local_settings.py',
                     '/secret_settings.py',
                     '/appsettings.json',
                     '/appsettings.Development.json',
                     '/database.yml',
                     '/secrets.yml',
                     '/credentials.yml',
                     '/Dockerfile',
                     '/docker-compose.yml',
                     '/docker-compose.override.yml',
                     '/Jenkinsfile',
                     '/.travis.yml',
                     '/.circleci/config.yml',
                     '/Makefile',
                     '/Gruntfile.js',
                     '/gulpfile.js',
                     '/webpack.config.js',
                     '/package.json',
                     '/package-lock.json',
                     '/yarn.lock',
                     '/requirements.txt',
                     '/Pipfile',
                     '/Pipfile.lock',
                     '/Gemfile',
                     '/Gemfile.lock',
                     '/Cargo.toml',
                     '/go.mod',
                     '/composer.json',
                     '/composer.lock',
                     '/pubspec.yaml',
                     '/.eslintrc',
                     '/.eslintrc.json',
                     '/.prettierrc',
                     '/.stylelintrc',
                     '/.editorconfig',
                     '/.vscode/settings.json',
                     '/.idea/workspace.xml',
                     '/phpinfo.php',
                     '/info.php',
                     '/test.php',
                     '/debug.php',
                     '/admin/',
                     '/administrator/',
                     '/wp-admin/',
                     '/admincp/',
                     '/api/',
                     '/rest/',
                     '/graphql/',
                     '/v1/',
                     '/v2/',
                     '/v3/',
                     '/docs/',
                     '/documentation/',
                     '/swagger/',
                     '/redoc/',
                     '/backup/',
                     '/backups/',
                     '/tmp/',
                     '/temp/',
                     '/cache/',
                     '/logs/',
                     '/log/',
                     '/debug/',
                     '/dev/',
                     '/test/',
                     '/phpmyadmin/',
                     '/pma/',
                     '/mysql/',
                     '/adminer/',
                     '/server-status',
                     '/server-info',
                     '/status',
                     '/cgi-bin/',
                     '/cgi-bin/test.cgi',
                     '/cgi-bin/php.cgi',
                     '/shell/',
                     '/cmd/',
                     '/exec/',
                     '/system/',
                     '/upload/',
                     '/uploads/',
                     '/files/',
                     '/media/',
                     '/assets/',
                     '/static/',
                     '/public/',
                     '/dist/',
                     '/build/',
                     '/node_modules/',
                     '/bower_components/',
                     '/vendor/',
                     '/.well-known/',
                     '/.well-known/security.txt',
                     '/robots.txt',
                     '/sitemap.xml',
                     '/sitemap.xml.gz',
                     '/crossdomain.xml',
                     '/clientaccesspolicy.xml',
                     '/security.txt',
                     '/humans.txt',
                     '/ads.txt'],
    'login_field_hints': {   'pass': ['pass', 'password', 'passwd', 'pwd'],
                             'user': [   'user',
                                         'username',
                                         'email',
                                         'login',
                                         'uname']},
    'safe_paths_whitelist': [   '/robots.txt',
                                '/.well-known/security.txt',
                                '/.well-known/',
                                '/favicon.ico',
                                '/sitemap.xml',
                                '/humans.txt',
                                '/ads.txt',
                                '/security.txt'],
    'security_payloads': {   'command_injection': [   '; id',
                                                      '| id',
                                                      '& id',
                                                      '`id`',
                                                      '; cat /etc/passwd',
                                                      '| cat /etc/passwd',
                                                      '; sleep 3',
                                                      '| sleep 3'],
                             'path_traversal': [   '../../../../etc/passwd',
                                                   '../../../../windows/win.ini',
                                                   '..%2F..%2F..%2F..%2Fetc/passwd',
                                                   '....//....//....//etc/passwd'],
                             'sql': [   "' OR '1'='1",
                                        "' OR 1=1--",
                                        "' UNION SELECT NULL--",
                                        "' AND 1=1--",
                                        "' AND 1=2--",
                                        "'; DROP TABLE users--",
                                        "' OR SLEEP(3)--"],
                             'xss': [   "<script>alert('XSS')</script>",
                                        "<img src=x onerror=alert('XSS')>",
                                        "javascript:alert('XSS')",
                                        "<svg/onload=alert('XSS')>",
                                        "<body onload=alert('XSS')>",
                                        '"><script>alert(String.fromCharCode(88,83,83))</script>']},
    'test_parameters': [   'q',
                           'query',
                           'search',
                           's',
                           'keyword',
                           'term',
                           'id',
                           'user',
                           'username',
                           'email',
                           'mail',
                           'page',
                           'p',
                           'offset',
                           'limit',
                           'per_page',
                           'sort',
                           'order',
                           'dir',
                           'filter',
                           'f',
                           'cat',
                           'category',
                           'tag',
                           'type',
                           'status',
                           'name',
                           'title',
                           'description',
                           'content',
                           'url',
                           'redirect',
                           'next',
                           'return',
                           'goto',
                           'file',
                           'path',
                           'doc',
                           'download',
                           'view',
                           'action',
                           'method',
                           'mode',
                           'format',
                           'callback'],
    'user_agents': [   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36',
                       'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                       'AppleWebKit/605.1.15',
                       'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) '
                       'Gecko/20100101 Firefox/120.0',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) '
                       'Gecko/20100101 Firefox/120.0',
                       'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                       'AppleWebKit/537.36',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Edge/119.0.0.0']}
STATUS_META = {   'FAIL': {'ansi': '\x1b[1;31m', 'css': 'fail', 'icon': '[-] ', 'orden': 2},
    'INFO': {'ansi': '\x1b[1;36m', 'css': 'info', 'icon': '[*] ', 'orden': 4},
    'PASS': {'ansi': '\x1b[1;32m', 'css': 'pass', 'icon': '[+] ', 'orden': 0},
    'SKIP': {'ansi': '\x1b[0;37m', 'css': 'skip', 'icon': '[?] ', 'orden': 3},
    'WARN': {'ansi': '\x1b[1;33m', 'css': 'warn', 'icon': '[!] ', 'orden': 1}}
STATUS_META_DEFAULT = {'ansi': '\x1b[0;37m', 'css': 'skip', 'icon': '[*] ', 'orden': 9}
TEST_METADATA = {   'API Discovery': {   'grupo': 'Auditoria Avanzada',
                         'owasp': 'General',
                         'severidad': 'info'},
    'Archivos Estaticos Optimizados': {   'grupo': 'Arquitectura y '
                                                   'Configuracion',
                                          'owasp': 'A02:2025 - Security '
                                                   'Misconfiguration',
                                          'severidad': 'baja'},
    'Auditoria JWT': {   'grupo': 'Seguridad OWASP Top 10',
                         'owasp': 'A07:2025 - Identification and Authentication Failures',
                         'severidad': 'critica'},
    'Auditoria IDOR (Doble Sesion)': {   'grupo': 'Seguridad OWASP Top 10',
                                         'owasp': 'A01:2025 - Broken Access Control',
                                         'severidad': 'critica'},
    'Bypass de 403': {   'grupo': 'Seguridad OWASP Top 10',
                         'owasp': 'A01:2025 - Broken Access Control',
                         'severidad': 'critica'},
    'Calibracion Soft-404': {   'grupo': 'Auditoria Avanzada',
                                'owasp': 'General',
                                'severidad': 'info'},
    'Certificado SSL/TLS': {   'grupo': 'Seguridad OWASP Top 10',
                               'owasp': 'A04:2025 - Cryptographic Failures',
                               'severidad': 'alta'},
    'Dependency Scan': {   'grupo': 'Auditoria Avanzada',
                           'owasp': 'A03:2025 - Software Supply Chain Failures',
                           'severidad': 'media'},
    'Descubrimiento (Crawler)': {   'grupo': 'Auditoria Avanzada',
                                    'owasp': 'General',
                                    'severidad': 'info'},
    'Directory / Path Traversal': {   'grupo': 'Seguridad OWASP Top 10',
                                      'owasp': 'A01:2025 - Broken Access '
                                               'Control',
                                      'severidad': 'critica'},
    'Diseno Responsive': {   'grupo': 'Experiencia de Usuario',
                             'owasp': 'UX',
                             'severidad': 'baja'},
    'Exposicion de Secretos en JS': {   'grupo': 'Seguridad OWASP Top 10',
                                        'owasp': 'A02:2025 - Security '
                                                 'Misconfiguration',
                                        'severidad': 'critica'},
    'GraphQL Introspection': {   'grupo': 'Seguridad OWASP Top 10',
                                 'owasp': 'A02:2025 - Security Misconfiguration',
                                 'severidad': 'media'},
    'HTTPS Obligatorio': {   'grupo': 'Seguridad OWASP Top 10',
                             'owasp': 'A04:2025 - Cryptographic Failures',
                             'severidad': 'alta'},
    'Headers Seguridad': {   'grupo': 'Seguridad OWASP Top 10',
                             'owasp': 'A02:2025 - Security Misconfiguration',
                             'severidad': 'media'},
    'Inyeccion SQL (SQLi)': {   'grupo': 'Seguridad OWASP Top 10',
                                'owasp': 'A05:2025 - Injection',
                                'severidad': 'critica'},
    'Inyeccion SQL (SQLi) - Sospecha': {   'grupo': 'Seguridad OWASP Top 10',
                                           'owasp': 'A05:2025 - Injection',
                                           'severidad': 'media'},
    'Inyeccion XSS Reflejado': {   'grupo': 'Seguridad OWASP Top 10',
                                   'owasp': 'A05:2025 - Injection',
                                   'severidad': 'critica'},
    'JS Static Analysis': {   'grupo': 'Auditoria Avanzada',
                              'owasp': 'A02:2025 - Security Misconfiguration',
                              'severidad': 'alta'},
    'JWT Claims Sensibles': {   'grupo': 'Seguridad OWASP Top 10',
                                'owasp': 'A07:2025 - Identification and Authentication Failures',
                                'severidad': 'media'},
    'JWT Firma No Validada': {   'grupo': 'Seguridad OWASP Top 10',
                                 'owasp': 'A07:2025 - Identification and Authentication Failures',
                                 'severidad': 'critica'},
    'JWT Secreto HMAC Debil': {   'grupo': 'Seguridad OWASP Top 10',
                                  'owasp': 'A07:2025 - Identification and Authentication Failures',
                                  'severidad': 'critica'},
    'JWT Sin Expiracion': {   'grupo': 'Seguridad OWASP Top 10',
                              'owasp': 'A07:2025 - Identification and Authentication Failures',
                              'severidad': 'baja'},
    'JWT Sin Firma (alg none)': {   'grupo': 'Seguridad OWASP Top 10',
                                    'owasp': 'A07:2025 - Identification and Authentication Failures',
                                    'severidad': 'critica'},
    'Login / Autenticacion': {   'grupo': 'Seguridad OWASP Top 10',
                                 'owasp': 'A07:2025 - Identification and '
                                          'Authentication Failures',
                                 'severidad': 'alta'},
    'OS Command Injection': {   'grupo': 'Seguridad OWASP Top 10',
                                 'owasp': 'A05:2025 - Injection',
                                 'severidad': 'critica'},
    'Open Redirect Inseguro': {   'grupo': 'Seguridad OWASP Top 10',
                                  'owasp': 'A07:2025 - Identification and '
                                           'Authentication Failures',
                                  'severidad': 'media'},
    'Path Scan': {   'grupo': 'Auditoria Avanzada',
                     'owasp': 'General',
                     'severidad': 'alta'},
    'Performance': {   'grupo': 'Experiencia de Usuario',
                       'owasp': 'UX',
                       'severidad': 'baja'},
    'SPA Discovery': {   'grupo': 'Auditoria Avanzada',
                         'owasp': 'General',
                         'severidad': 'info'},
    'SSRF / Cloud Metadata': {   'grupo': 'Seguridad OWASP Top 10',
                                 'owasp': 'A01:2025 - Broken Access Control',
                                 'severidad': 'critica'},
    'SSRF - Sospecha': {   'grupo': 'Seguridad OWASP Top 10',
                           'owasp': 'A01:2025 - Broken Access Control',
                           'severidad': 'media'},
    'SSTI (Template Injection)': {   'grupo': 'Seguridad OWASP Top 10',
                                      'owasp': 'A05:2025 - Injection',
                                      'severidad': 'critica'},
    'Tech Detection': {   'grupo': 'Auditoria Avanzada',
                          'owasp': 'General',
                          'severidad': 'info'}}
DEFAULT_METADATA = {'grupo': 'Otras Pruebas', 'owasp': 'General', 'severidad': 'info'}

def barra_progreso(actual, total, longitud=30, prefijo="Progreso General:"):
    if total <= 0:
        return
    porcentaje = int((actual / total) * 100)
    completado = int((longitud * actual) // total)
    barra = '█' * completado + '-' * (longitud - completado)
    sys.stdout.write(f'\r{prefijo} [ {porcentaje:3d}% ] [ {barra} ]')
    sys.stdout.flush()
    if actual >= total:
        print()

