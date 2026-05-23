"""
API Documentation Discovery for 0-Day Hunting
Discovers exposed API documentation that reveals hidden endpoints
"""
from urllib.parse import urljoin
from typing import Dict, List, Any
import json
from detectors.registry import register_active


class APIDocsDiscovery:
    """
    Discovers exposed API documentation:
    - Swagger/OpenAPI specs
    - GraphQL introspection
    - API documentation pages
    - Postman collections
    - WADL files
    """

    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.findings = []
        self.discovered_endpoints = []

        # Common API documentation paths
        self.doc_paths = [
            # Swagger/OpenAPI
            '/swagger',
            '/swagger-ui',
            '/swagger-ui.html',
            '/swagger/index.html',
            '/api/swagger',
            '/api/swagger-ui',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/api/openapi.json',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/api-docs',
            '/api/docs',
            '/docs',
            '/documentation',

            # GraphQL
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/graphql/console',

            # RAML/WADL
            '/api.raml',
            '/application.wadl',
            '/api/application.wadl',

            # Postman
            '/postman',
            '/postman_collection.json',
            '/api/postman',

            # API Blueprint
            '/api.md',
            '/api-blueprint',

            # Other common paths
            '/redoc',
            '/rapidoc',
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/api/rest',
        ]

    def run(self) -> Dict[str, Any]:
        """Main execution method"""
        try:
            # Check each documentation path
            for path in self.doc_paths:
                url = urljoin(self.target, path)
                doc_info = self.check_api_docs(url)

                if doc_info:
                    self.findings.append(doc_info)

                    # Try to extract endpoints if it's a spec file
                    if doc_info['type'] in ['swagger', 'openapi']:
                        self.extract_swagger_endpoints(url)
                    elif doc_info['type'] == 'graphql':
                        self.extract_graphql_schema(url)

            return {
                'vulnerable': len(self.findings) > 0,
                'severity': self.calculate_severity(),
                'findings': self.findings,
                'documentation_count': len(self.findings),
                'endpoints_discovered': len(self.discovered_endpoints),
                'details': {
                    'swagger_docs': [f for f in self.findings if f['type'] in ['swagger', 'openapi']],
                    'graphql_endpoints': [f for f in self.findings if f['type'] == 'graphql'],
                    'api_docs': [f for f in self.findings if f['type'] == 'api_docs'],
                    'discovered_endpoints': self.discovered_endpoints[:50],  # Limit to 50
                }
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'findings': []
            }

    def check_api_docs(self, url: str) -> Dict[str, Any]:
        """Check if API documentation exists at URL"""
        try:
            import requests
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)

            if response.status_code != 200:
                return None

            content = response.text.lower()
            content_type = response.headers.get('content-type', '').lower()

            # Detect Swagger/OpenAPI
            if any(keyword in content for keyword in ['swagger', 'openapi', 'swaggerui']):
                return {
                    'type': 'swagger',
                    'severity': 'high',
                    'url': url,
                    'description': 'Swagger/OpenAPI documentation exposed',
                    'details': 'May reveal all API endpoints including internal ones'
                }

            # Detect GraphQL
            if 'graphql' in content or 'graphiql' in content:
                return {
                    'type': 'graphql',
                    'severity': 'high',
                    'url': url,
                    'description': 'GraphQL endpoint/console exposed',
                    'details': 'Introspection may reveal entire API schema'
                }

            # Detect JSON/YAML API specs
            if 'application/json' in content_type or url.endswith(('.json', '.yaml', '.yml')):
                try:
                    data = json.loads(response.text)
                    if 'swagger' in data or 'openapi' in data or 'paths' in data:
                        return {
                            'type': 'openapi',
                            'severity': 'high',
                            'url': url,
                            'description': 'OpenAPI specification file exposed',
                            'details': f"Contains {len(data.get('paths', {}))} API endpoints"
                        }
                except:
                    pass

            # Detect API documentation pages
            if any(keyword in content for keyword in ['api documentation', 'rest api', 'api reference']):
                return {
                    'type': 'api_docs',
                    'severity': 'medium',
                    'url': url,
                    'description': 'API documentation page exposed',
                    'details': 'May contain undocumented endpoints and examples'
                }

            return None
        except:
            return None

    def extract_swagger_endpoints(self, url: str):
        """Extract endpoints from Swagger/OpenAPI spec"""
        try:
            import requests
            response = requests.get(url, timeout=10, verify=False)
            data = json.loads(response.text)

            paths = data.get('paths', {})

            for path, methods in paths.items():
                for method in methods.keys():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        endpoint = {
                            'method': method.upper(),
                            'path': path,
                            'description': methods[method].get('summary', 'No description')
                        }
                        self.discovered_endpoints.append(endpoint)
        except:
            pass

    def extract_graphql_schema(self, url: str):
        """Try GraphQL introspection query"""
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        description
                    }
                    queryType { name }
                    mutationType { name }
                }
            }
            """
        }

        try:
            import requests
            response = requests.post(
                url,
                json=introspection_query,
                timeout=10,
                verify=False,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    types = data['data']['__schema'].get('types', [])

                    self.findings.append({
                        'type': 'graphql_introspection',
                        'severity': 'high',
                        'url': url,
                        'description': 'GraphQL introspection enabled',
                        'details': f"Discovered {len(types)} GraphQL types"
                    })
        except:
            pass

    def calculate_severity(self) -> str:
        """Calculate overall severity"""
        if not self.findings:
            return 'info'
        severities = [f.get('severity', 'info') for f in self.findings]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        return 'low'


def detect(target: str) -> Dict[str, Any]:
    """Main detection function"""
    discovery = APIDocsDiscovery(target)
    return discovery.run()


class AsyncAPIDocsDiscovery:
    def __init__(self, session, target: str, *, verify_tls: bool = True):
        self.session = session
        self.target = target.rstrip("/")
        self.verify_tls = bool(verify_tls)
        self.findings: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.doc_paths = APIDocsDiscovery(target).doc_paths

    async def _get(self, url: str, *, allow_redirects: bool = True) -> Dict[str, Any] | None:
        ssl_opt = None if self.verify_tls else False
        try:
            async with self.session.get(url, allow_redirects=allow_redirects, ssl=ssl_opt) as resp:
                if resp.status != 200:
                    return None
                text = await resp.text(errors="replace")
                return {
                    "status": resp.status,
                    "text": text,
                    "headers": dict(resp.headers),
                }
        except Exception:
            return None

    async def _post_json(self, url: str, payload: dict) -> dict | None:
        ssl_opt = None if self.verify_tls else False
        try:
            async with self.session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                ssl=ssl_opt,
            ) as resp:
                if resp.status != 200:
                    return None
                try:
                    return await resp.json(content_type=None)
                except Exception:
                    return None
        except Exception:
            return None

    def _calculate_severity(self) -> str:
        if not self.findings:
            return "info"
        severities = [f.get("severity", "info") for f in self.findings]
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    async def _check_api_docs(self, url: str) -> Dict[str, Any] | None:
        res = await self._get(url, allow_redirects=True)
        if not res:
            return None
        content = (res.get("text") or "").lower()
        headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
        content_type = (headers.get("content-type") or "").lower()

        if any(keyword in content for keyword in ["swagger", "openapi", "swaggerui"]):
            return {
                "type": "swagger",
                "severity": "high",
                "url": url,
                "description": "Swagger/OpenAPI documentation exposed",
                "details": "May reveal all API endpoints including internal ones",
            }

        if "graphql" in content or "graphiql" in content:
            return {
                "type": "graphql",
                "severity": "high",
                "url": url,
                "description": "GraphQL endpoint/console exposed",
                "details": "Introspection may reveal entire API schema",
            }

        if "application/json" in content_type or url.endswith((".json", ".yaml", ".yml")):
            try:
                data = json.loads(res.get("text") or "{}")
                if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                    paths = data.get("paths", {}) if isinstance(data.get("paths", {}), dict) else {}
                    return {
                        "type": "openapi",
                        "severity": "high",
                        "url": url,
                        "description": "OpenAPI specification file exposed",
                        "details": f"Contains {len(paths)} API endpoints",
                    }
            except Exception:
                pass

        if any(keyword in content for keyword in ["api documentation", "rest api", "api reference"]):
            return {
                "type": "api_docs",
                "severity": "medium",
                "url": url,
                "description": "API documentation page exposed",
                "details": "May contain undocumented endpoints and examples",
            }
        return None

    async def _extract_swagger_endpoints(self, url: str):
        res = await self._get(url, allow_redirects=True)
        if not res:
            return
        try:
            data = json.loads(res.get("text") or "{}")
            if not isinstance(data, dict):
                return
            paths = data.get("paths", {})
            if not isinstance(paths, dict):
                return
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method in methods.keys():
                    if str(method).upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        meta = methods.get(method, {}) if isinstance(methods.get(method, {}), dict) else {}
                        self.discovered_endpoints.append(
                            {
                                "method": str(method).upper(),
                                "path": path,
                                "description": meta.get("summary", "No description"),
                            }
                        )
        except Exception:
            return

    async def _extract_graphql_schema(self, url: str):
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        description
                    }
                    queryType { name }
                    mutationType { name }
                }
            }
            """
        }
        data = await self._post_json(url, introspection_query)
        if not data:
            return
        try:
            if "data" in data and data.get("data") and "__schema" in data.get("data", {}):
                types = data["data"]["__schema"].get("types", [])
                self.findings.append(
                    {
                        "type": "graphql_introspection",
                        "severity": "high",
                        "url": url,
                        "description": "GraphQL introspection enabled",
                        "details": f"Discovered {len(types) if isinstance(types, list) else 0} GraphQL types",
                    }
                )
        except Exception:
            return

    async def run(self) -> Dict[str, Any]:
        for path in self.doc_paths:
            url = urljoin(self.target, path)
            doc_info = await self._check_api_docs(url)
            if not doc_info:
                continue
            self.findings.append(doc_info)
            if doc_info.get("type") in ["swagger", "openapi"]:
                await self._extract_swagger_endpoints(url)
            elif doc_info.get("type") == "graphql":
                await self._extract_graphql_schema(url)

        return {
            "vulnerable": len(self.findings) > 0,
            "severity": self._calculate_severity(),
            "findings": self.findings,
            "documentation_count": len(self.findings),
            "endpoints_discovered": len(self.discovered_endpoints),
            "details": {
                "swagger_docs": [f for f in self.findings if f.get("type") in ["swagger", "openapi"]],
                "graphql_endpoints": [f for f in self.findings if f.get("type") == "graphql"],
                "api_docs": [f for f in self.findings if f.get("type") == "api_docs"],
                "discovered_endpoints": self.discovered_endpoints[:50],
            },
        }


@register_active
async def api_docs_discovery(session, url: str, context: Dict[str, Any]):
    """Async detector for exposed API docs (Swagger/OpenAPI/GraphQL consoles/specs)."""
    verify_tls = context.get("verify_tls", True)
    discovery = AsyncAPIDocsDiscovery(session, url, verify_tls=bool(verify_tls))
    result = await discovery.run()

    findings = []
    for f in (result or {}).get("findings", []) or []:
        findings.append(
            {
                "url": f.get("url", url),
                "type": "Exposed API Documentation",
                "severity": f.get("severity", "medium"),
                "description": f.get("description", "API documentation exposed"),
                "evidence": f.get("details") or f.get("type") or "API docs detected",
                "how_found": "api_docs_discovery",
                "detector": "api_docs_discovery",
            }
        )
    return findings
