# mcpguard

Security scanner and firewall for MCP (Model Context Protocol) servers. Checks your configs for known issues, blocks sketchy tool calls at runtime, and keeps audit logs.

Maps to the **OWASP MCP Top 10** (2026).

## Why

MCP is everywhere now - Claude, Cursor, VS Code, OpenAI. But most setups ship with zero security review. Studies found 82% of MCP implementations have path traversal issues, 67% have code injection vectors, and about 5.5% of public servers have tool poisoning baked in.

This tool helps you catch that stuff before it bites you.

## Quick Start

```bash
npm install -g @gtprojects/mcpguard

# scan your MCP config
mcpguard scan

# generate a starter policy
mcpguard init

# run the firewall proxy
mcpguard proxy --policy mcpguard.policy.yaml --port 9090
```

## Commands

### `mcpguard scan [target]`

Scans MCP server configs for security issues.

```bash
mcpguard scan                              # scan current directory
mcpguard scan claude_desktop_config.json   # scan a specific file
mcpguard scan --format json                # JSON output
mcpguard scan --format sarif               # SARIF for GitHub Code Scanning
mcpguard scan --ci                         # exit code 1 on critical/high
mcpguard scan --severity high              # only show high+ severity
```

### `mcpguard proxy`

Sits between your agent and MCP servers. Checks every tool call against your policy, blocks anything that doesn't pass, and logs everything.

```bash
mcpguard proxy --port 9090
mcpguard proxy --policy mcpguard.policy.yaml --port 9090
mcpguard proxy --policy mcpguard.policy.yaml --upstream http://localhost:3000
mcpguard proxy --policy mcpguard.policy.yaml --audit-file ./audit.log
```

### `mcpguard init`

Drops a default policy file you can customize.

```bash
mcpguard init
mcpguard init --output custom-policy.yaml
```

## Policy Format

Policies are YAML. You define rules with conditions and actions (allow/deny/audit):

```yaml
version: "1.0"
name: my-security-policy
description: Custom security rules

rules:
  - id: deny-shell-exec
    name: Block shell execution
    action: deny
    priority: 100
    conditions:
      - field: tool.name
        operator: matches
        value: "(exec|shell|bash|cmd)"

  - id: audit-file-writes
    name: Audit all file writes
    action: audit
    priority: 50
    conditions:
      - field: tool.name
        operator: contains
        value: write
```

### Condition Fields

| Field | What it matches |
|-------|-----------------|
| `tool.name` | Tool name |
| `tool.description` | Tool description text |
| `param.name` | Parameter names (comma-separated) |
| `param.value` | Parameter values (comma-separated) |
| `server.name` | MCP server name |
| `server.url` | MCP server URL |

### Operators

`equals`, `contains`, `matches` (regex), `startsWith`, `endsWith`, `in` (list)

## What It Checks

| ID | Category | What we look for |
|----|----------|------------------|
| MCP01 | Tool Poisoning | Hidden instructions, zero-width chars |
| MCP02 | Excessive Permissions | Root-level access, wildcard permissions |
| MCP03 | Insecure Transport | Unencrypted HTTP, SSRF via metadata endpoints |
| MCP04 | Command Injection | Shell metacharacters in args, template injection (Jinja, EJS, Mustache) |
| MCP05 | Path Traversal | `..` in paths, access to sensitive system paths (.ssh, .aws, .kube, .env) |
| MCP06 | Secret Exposure | 15+ token patterns (AWS, Stripe, GitHub, Slack, etc.), sensitive env vars with literal values |
| MCP07 | Insecure Defaults | Missing security config for remote servers, Docker socket exposure |
| MCP08 | Input Validation | Shell interpreters, curl\|sh pipe-to-shell patterns |
| MCP09 | Audit Gaps | No logging configured |
| MCP10 | Privilege Escalation | sudo, --privileged, writable host mounts in containers |

## Try It

Scan the included example configs to see mcpguard in action:

```bash
# Scan a deliberately dangerous config (lots of findings)
mcpguard scan examples/dangerous-config.json

# Scan a clean config (should pass)
mcpguard scan examples/safe-config.json
```

## GitHub Actions

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g @gtprojects/mcpguard
      - run: mcpguard scan --ci --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Programmatic API

```typescript
import { Scanner, PolicyEngine, McpFirewall, AuditLogger } from '@gtprojects/mcpguard';

const scanner = new Scanner();
const results = scanner.scanFile('claude_desktop_config.json');
console.log(results.summary);

const engine = new PolicyEngine();
engine.loadFromFile('mcpguard.policy.yaml');
const decision = engine.evaluate({
  toolName: 'shell_exec',
  paramNames: ['command'],
  paramValues: ['rm -rf /'],
});
console.log(decision); // { allowed: false, action: 'deny', ... }
```

## Contributing

PRs welcome. Open an issue first if it's anything big.

```bash
git clone https://github.com/GT-Projects256/mcpguard.git
cd mcpguard
npm install
npm test
```

## License

MIT
