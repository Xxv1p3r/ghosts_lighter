# -*- coding: utf-8 -*-
"""
Motor de detección de introspección GraphQL habilitada.

Enfoque en dos sondas por endpoint:
1. `{__typename}` confirma que el endpoint habla GraphQL de verdad (es una
   consulta válida que se permite incluso con la introspección deshabilitada),
   evitando confundir un 404/HTML con un servidor GraphQL.
2. `{__schema{...}}` comprueba si la introspección está habilitada y, de
   estarlo, extrae el tipo de consulta, si hay mutaciones y los nombres de
   campos sensibles presentes en el schema.

Se prueban tanto POST con JSON como GET con `?query=`, ya que algunos
servidores solo aceptan uno de los dos transportes.
"""

import json
import re

# Rutas típicas donde se publica un endpoint GraphQL
GRAPHQL_PATHS = [
    '/graphql',
    '/graphql/',
    '/api/graphql',
    '/api/v1/graphql',
    '/v1/graphql',
    '/graphql/v1',
    '/gql',
    '/graphiql',
    '/playground',
    '/graphql/console',
    '/query',
    '/graphql.php',
]

QUERY_TYPENAME = '{__typename}'
QUERY_INTROSPECCION = '{__schema{queryType{name} mutationType{name} types{name fields{name}}}}'

# Nombres de campo/rol que, si aparecen en el schema, merecen resaltarse
SENSITIVE_PATTERN = re.compile(
    r'"([A-Za-z0-9_]*(?:password|passwd|secret|token|apikey|api_key|creditcard|'
    r'credit_card|ssn|privatekey|private_key|hash|salt)[A-Za-z0-9_]*)"',
    re.I
)


class GraphQLIntrospectionScanner:
    def __init__(self, session, timeout=8):
        self.session = session
        self.timeout = timeout
        # Estado para reporte: endpoints confirmados como GraphQL
        self.endpoints_graphql = []

    @staticmethod
    def _json(resp):
        if resp is None:
            return None
        try:
            return json.loads(resp.text or '')
        except Exception:
            return None

    def _pedir(self, url, query):
        """
        Envía la consulta por POST JSON y cae a GET `?query=` si el POST no
        devuelve una respuesta JSON (por ejemplo 405 Method Not Allowed).
        """
        try:
            resp = self.session.post(url, json={'query': query}, timeout=self.timeout)
            if self._json(resp) is not None:
                return resp
        except Exception:
            pass

        try:
            return self.session.get(url, params={'query': query}, timeout=self.timeout)
        except Exception:
            return None

    @staticmethod
    def _es_graphql(resp):
        data = GraphQLIntrospectionScanner._json(resp)
        if not isinstance(data, dict):
            return False
        payload = data.get('data')
        return isinstance(payload, dict) and '__typename' in payload

    @staticmethod
    def _extraer_schema(resp):
        data = GraphQLIntrospectionScanner._json(resp)
        if not isinstance(data, dict):
            return None
        payload = data.get('data')
        if isinstance(payload, dict) and isinstance(payload.get('__schema'), dict):
            return payload['__schema']
        return None

    @staticmethod
    def _nombres_sensibles(texto):
        vistos = []
        for match in SENSITIVE_PATTERN.finditer(texto or ''):
            nombre = match.group(1)
            if nombre not in vistos:
                vistos.append(nombre)
            if len(vistos) >= 6:
                break
        return vistos

    def scan_endpoint(self, url):
        """
        Devuelve la lista de hallazgos para un endpoint candidato.
        Vacía si el endpoint no es GraphQL o si la introspección está deshabilitada.
        """
        findings = []

        confirmacion = self._pedir(url, QUERY_TYPENAME)
        if not self._es_graphql(confirmacion):
            return findings

        self.endpoints_graphql.append(url)

        introspeccion = self._pedir(url, QUERY_INTROSPECCION)
        schema = self._extraer_schema(introspeccion)
        if schema is None:
            return findings

        query_type = (schema.get('queryType') or {}).get('name') or 'desconocido'
        mutation_type = (schema.get('mutationType') or {}).get('name')
        tipos = schema.get('types')
        n_tipos = len(tipos) if isinstance(tipos, list) else 0
        sensibles = self._nombres_sensibles(introspeccion.text if introspeccion else '')

        detalle = (
            f"Introspeccion GraphQL habilitada en {url}: el schema expone {n_tipos} tipos "
            f"y el tipo de consulta '{query_type}'"
        )
        if mutation_type:
            detalle += f"; mutaciones disponibles ('{mutation_type}')"
        if sensibles:
            detalle += f"; nombres sensibles en el schema: {', '.join(sensibles)}"

        findings.append({
            'technique': 'Introspection Enabled',
            'severity': 'media',
            'detalle': detalle,
            'evidence': f"Query: {QUERY_INTROSPECCION}",
            'url': url,
            'cwe': 'CWE-200'
        })
        return findings
