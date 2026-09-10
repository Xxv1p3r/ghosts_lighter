# GHOSTS LIGHTER ⚡

**Assessment Engine · Local · Fast · Actionable · Open Source**

GHOSTS LIGHTER es un motor de evaluación de seguridad web (*DAST*) diseñado para ejecutar auditorías rápidas y automatizadas alineadas con **OWASP Top 10 (2025)**. Combina reconocimiento activo mediante crawling (con soporte SPA vía Playwright), análisis estático de bundles JavaScript, detección de vulnerabilidades web comunes y exportación de reportes multiformato (incluyendo SARIF 2.1.0 para CI/CD).

---

## 🚀 Características Principales

- 🕷️ **Crawler con análisis de SPA**: Mapeo recursivo de enlaces y formularios, con renderizado dinámico opcional en Chromium headless.
- 🔍 **Análisis estático de JavaScript**: Detección pasiva de endpoints de API y credenciales / secretos hardcodeados con ofuscación automática.
- 🎯 **Pruebas DAST OWASP Top 10**:
  - Inyección SQL (SQLi por firma y anomalías HTTP 500 contra baseline).
  - Cross-Site Scripting (XSS) reflejado.
  - Directory / Path Traversal (LFI).
  - Open Redirect inseguro.
  - Auditoría de cabeceras de seguridad (HSTS, CSP, X-Frame-Options, etc.).
  - Validación de certificados SSL/TLS y redirección HTTPS.
  - Detección de stack tecnológico y dependencias expuestas (`package.json`, `requirements.txt`).
- 🛡️ **Calibración Soft-404**: Algoritmo dinámico anti-falsos positivos para SPAs y servidores con fallback 200 OK.
- 📊 **Reportería Multiformato**:
  - **HTML**: Dashboard interactivo con tema oscuro y categorización OWASP.
  - **JSON**: Formato estándar estructurado para integraciones.
  - **SARIF 2.1.0**: Compatible nativamente con GitHub Security y flujos CI/CD.
  - **TXT**: Resumen ejecutivo en consola y texto plano.

---

## 📦 Instalación

### Requisitos
- Python 3.8+
- `requests >= 2.28.0`

### 1. Clonar e instalar en modo editable:
```bash
git clone https://github.com/v1p3rx/ghosts-lighter.git
cd ghosts-lighter
pip install -e .
```

### 2. (Opcional) Soporte para renderizado SPA con Playwright:
```bash
pip install -e ".[browser]"
playwright install chromium
```

---

## 💻 Uso

Puedes ejecutarlo a través del comando CLI instalado o directamente con Python:

```bash
# Escaneo básico
ghosts-lighter http://ejemplo.local:3000

# O ejecutando el script directamente:
python3 ghosts_lighter.py http://ejemplo.local:3000
```

### Con autenticación y wordlist personalizada:
```bash
ghosts-lighter http://127.0.0.1:8080 \
  --username admin \
  --password password \
  --login-path /login \
  --wl common.txt \
  -o reporte_final.html
```

### Opciones CLI:
| Parámetro | Descripción |
|---|---|
| `target_url` | URL objetivo a auditar (ej: `http://127.0.0.1:3000`) |
| `--username` | Usuario para autenticación automática (default: `admin`) |
| `--password` | Contraseña para autenticación (default: `password`) |
| `--login-path` | Ruta específica del formulario de login (ej: `/login.php`) |
| `--max-pages` | Máximo de páginas a recorrer en el crawl (default: 40) |
| `--max-depth` | Profundidad máxima del crawler (default: 2) |
| `--no-selenium` / `--no-browser` | Desactiva renderizado dinámico con Playwright |
| `--wl, --wordlist` | Diccionario personalizado para escaneo de rutas sensibles |
| `-o, --output` | Nombre o ruta del archivo de reporte generado |

---

## 📄 Licencia

Este proyecto está licenciado bajo los términos de la licencia MIT.  
Autor: **v1p3rx**
