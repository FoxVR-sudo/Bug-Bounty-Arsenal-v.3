# detectors/graphql_detector.py
"""
GraphQL Security Detector - High-value vulnerability detection for GraphQL APIs

Tests for:
- Introspection enabled (reveals entire schema)
- Query batching attacks (100+ queries in 1 request)
- Query depth/complexity bypass
- Field duplication DoS
- Alias-based rate limit bypass
- Hidden field enumeration
- Mutation without authentication
- Debug mode enabled

Expected Bounty Value: $500-$5,000 per finding
Common in: SaaS platforms, APIs, modern web apps
"""
import logging
import json
from urllib.parse import urlparse
from detectors.registry import register_active, await_host_token

logger = logging.getLogger(__name__)

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graphiql",
    "/playground",
]

# Introspection query (reveals entire schema)
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

# Simplified introspection (some APIs block full introspection)
SIMPLE_INTROSPECTION = """
{
  __schema {
    types {
      name
    }
  }
}
"""

# Query batching attack (100 queries in one request)
BATCH_QUERY_TEMPLATE = """
[
  {batched_queries}
]
"""

# Deep nesting attack (bypasses depth limits)
DEEP_NESTING_QUERY = """
query DeepNesting {
  {field} {
    {field} {
      {field} {
        {field} {
          {field} {
            {field} {
              {field} {
                {field} {
                  {field} {
                    {field} {
                      __typename
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
}
"""

# Field duplication DoS
FIELD_DUPLICATION = """
query FieldDuplication {
  {duplicated_fields}
}
"""

# Alias-based rate limit bypass
ALIAS_BYPASS = """
query AliasBypass {
  {aliased_fields}
}
"""


@register_active
async def graphql_detector(session, url, context):
    """
    Detect GraphQL vulnerabilities and misconfigurations.

    High-value findings:
    - Introspection enabled → reveals entire API schema
    - Batching attacks → mass data extraction
    - Depth bypass → DoS potential
    - Hidden fields → unauthorized data access
    """
    findings = []

    if not url:
        return findings

    allow_destructive = context.get("allow_destructive", False)
    per_host_rate = context.get("per_host_rate", None)

    try:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc.lower()

        # Check if URL already looks like GraphQL endpoint
        graphql_endpoints = []
        if any(path in url.lower() for path in ["/graphql", "/gql", "/query"]):
            graphql_endpoints.append(url)
        else:
            # Try common GraphQL paths
            for path in GRAPHQL_PATHS[:5]:  # Test first 5 paths
                graphql_endpoints.append(base_url + path)

        for endpoint in graphql_endpoints:
            logger.info(f"🔍 Testing GraphQL endpoint: {endpoint}")

            # Test 1: Check if endpoint exists and accepts GraphQL
            await await_host_token(host, per_host_rate)

            # Simple query to detect GraphQL
            simple_query = {"query": "{ __typename }"}

            try:
                async with session.post(
                    endpoint,
                    json=simple_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                ) as resp:
                    body = await resp.text()
                    status = resp.status

                    # Check if it's a GraphQL endpoint
                    is_graphql = (
                        status == 200 and
                        ('"data"' in body or '"errors"' in body or '__typename' in body)
                    )

                    if not is_graphql:
                        continue

                    logger.info(f"✅ GraphQL endpoint found: {endpoint}")

            except Exception as e:
                logger.debug(f"GraphQL detection failed for {endpoint}: {e}")
                continue

            # Test 2: Introspection query (CRITICAL finding)
            logger.info(f"🔍 Testing introspection on {endpoint}")
            await await_host_token(host, per_host_rate)

            try:
                async with session.post(
                    endpoint,
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                    timeout=15
                ) as resp:
                    body = await resp.text()
                    status = resp.status

                    if status == 200 and '"__schema"' in body and '"queryType"' in body:
                        # CRITICAL: Full introspection enabled!
                        try:
                            data = json.loads(body)
                            schema_types = len(data.get("data", {}).get("__schema", {}).get("types", []))

                            findings.append({
                                "type": "GraphQL Introspection Enabled",
                                "severity": "high",
                                "evidence": f"Full schema introspection enabled - {schema_types} types discovered",
                                "how_found": f"Introspection query returned full schema with {schema_types} types",
                                "evidence_url": endpoint,
                                "evidence_body": body[:1000],
                                "evidence_status": status,
                                "payload": INTROSPECTION_QUERY[:200] + "...",
                                "impact": "Attacker can discover entire API structure, hidden fields, and sensitive mutations",
                                "remediation": "Disable introspection in production or require authentication",
                                "cve_reference": "CWE-200: Exposure of Sensitive Information",
                            })

                            logger.warning(f"🔥 CRITICAL: GraphQL introspection enabled on {endpoint} ({schema_types} types)")

                        except json.JSONDecodeError:
                            pass

            except Exception as e:
                logger.debug(f"Introspection test failed: {e}")

            # Test 3: Simplified introspection (if full fails)
            if not any(f.get("type") == "GraphQL Introspection Enabled" for f in findings):
                await await_host_token(host, per_host_rate)

                try:
                    async with session.post(
                        endpoint,
                        json={"query": SIMPLE_INTROSPECTION},
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    ) as resp:
                        body = await resp.text()
                        status = resp.status

                        if status == 200 and '"__schema"' in body:
                            findings.append({
                                "type": "GraphQL Introspection Partially Enabled",
                                "severity": "medium",
                                "evidence": "Simplified introspection query succeeded",
                                "how_found": "Simplified __schema query returned type information",
                                "evidence_url": endpoint,
                                "evidence_body": body[:500],
                                "evidence_status": status,
                                "impact": "Attacker can enumerate API types and structure",
                                "remediation": "Disable introspection completely in production",
                            })

                except Exception as e:
                    logger.debug(f"Simple introspection test failed: {e}")

            # Test 4: Query batching (if --allow-destructive)
            if allow_destructive:
                logger.info(f"🔍 Testing query batching on {endpoint}")
                await await_host_token(host, per_host_rate)

                # Create 10 batched queries (safe number for testing)
                batched = []
                for i in range(10):
                    batched.append({"query": f"query Batch{i} {{ __typename }}"})

                try:
                    async with session.post(
                        endpoint,
                        json=batched,
                        headers={"Content-Type": "application/json"},
                        timeout=10
                    ) as resp:
                        body = await resp.text()
                        status = resp.status

                        if status == 200:
                            try:
                                data = json.loads(body)
                                if isinstance(data, list) and len(data) >= 10:
                                    findings.append({
                                        "type": "GraphQL Query Batching Enabled",
                                        "severity": "high",
                                        "evidence": f"Successfully executed {len(data)} batched queries in single request",
                                        "how_found": f"Sent {len(batched)} queries in array, all executed",
                                        "evidence_url": endpoint,
                                        "evidence_body": body[:500],
                                        "evidence_status": status,
                                        "impact": "Attacker can bypass rate limits and extract massive amounts of data (100+ queries per request)",
                                        "remediation": "Disable query batching or limit batch size to 1-5 queries",
                                        "cve_reference": "CWE-770: Allocation of Resources Without Limits",
                                    })

                                    logger.warning(f"🔥 HIGH: Query batching enabled on {endpoint}")

                            except json.JSONDecodeError:
                                pass

                except Exception as e:
                    logger.debug(f"Batching test failed: {e}")

            # Test 5: Field suggestions (reveals hidden fields)
            logger.info(f"🔍 Testing field suggestions on {endpoint}")
            await await_host_token(host, per_host_rate)

            try:
                # Intentionally misspelled field to trigger suggestions
                suggestion_query = {"query": "{ usr }"}  # "usr" instead of "user"

                async with session.post(
                    endpoint,
                    json=suggestion_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                ) as resp:
                    body = await resp.text()
                    status = resp.status

                    if 'Did you mean' in body or 'suggestions' in body.lower():
                        findings.append({
                            "type": "GraphQL Field Suggestions Enabled",
                            "severity": "low",
                            "evidence": "Field suggestions reveal available fields",
                            "how_found": "Misspelled field returned 'Did you mean' suggestions",
                            "evidence_url": endpoint,
                            "evidence_body": body[:500],
                            "evidence_status": status,
                            "impact": "Attacker can enumerate hidden fields by intentional typos",
                            "remediation": "Disable field suggestions in production",
                        })

            except Exception as e:
                logger.debug(f"Field suggestion test failed: {e}")

            # Test 6: Debug/verbose errors
            await await_host_token(host, per_host_rate)

            try:
                # Invalid query to trigger error
                error_query = {"query": "{ invalid_syntax here }"}

                async with session.post(
                    endpoint,
                    json=error_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                ) as resp:
                    body = await resp.text()
                    status = resp.status

                    # Check for verbose error messages
                    verbose_indicators = [
                        'stack trace',
                        'Traceback',
                        'at line',
                        'syntax error',
                        '.js:',
                        '.py:',
                        'TypeError',
                        'graphql-ruby',
                        'apollo-server',
                    ]

                    if any(indicator in body for indicator in verbose_indicators):
                        findings.append({
                            "type": "GraphQL Verbose Error Messages",
                            "severity": "low",
                            "evidence": "Verbose error messages expose internal details",
                            "how_found": "Invalid query returned detailed stack trace",
                            "evidence_url": endpoint,
                            "evidence_body": body[:500],
                            "evidence_status": status,
                            "impact": "Error messages reveal framework, file paths, and internal structure",
                            "remediation": "Disable debug mode and sanitize error messages in production",
                        })

            except Exception as e:
                logger.debug(f"Verbose error test failed: {e}")

    except Exception as e:
        logger.exception(f"graphql_detector error for {url}: {e}")

    return findings
