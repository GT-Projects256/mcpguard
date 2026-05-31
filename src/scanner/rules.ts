/**
 * Built-in scanner rules aligned to OWASP MCP Top 10
 */

import { ScanFinding, Severity, OwaspCategory, McpServerConfig } from '../types';

export interface ScanRule {
  id: string;
  name: string;
  category: OwaspCategory;
  severity: Severity;
  description: string;
  check: (serverName: string, config: McpServerConfig, rawContent?: string) => ScanFinding[];
}

// Helper: create a finding
function finding(
  rule: ScanRule,
  message: string,
  opts?: { file?: string; line?: number; evidence?: string; remediation?: string }
): ScanFinding {
  return {
    id: `${rule.id}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    rule: rule.id,
    severity: rule.severity,
    category: rule.category,
    message,
    ...opts,
  };
}

// Shorthand for creating the rule ref inside finding() calls
function ruleRef(id: string, category: OwaspCategory, severity: Severity): ScanRule {
  return { id, name: '', category, severity, description: '', check: () => [] };
}

export const BUILTIN_RULES: ScanRule[] = [
  // MCP01: Tool Poisoning
  {
    id: 'MCP01-001',
    name: 'Suspicious tool description patterns',
    category: 'MCP01:ToolPoisoning',
    severity: 'critical',
    description: 'Detects hidden instructions or manipulation patterns in tool descriptions',
    check: (_name, _config, rawContent) => {
      if (!rawContent) return [];
      const findings: ScanFinding[] = [];
      const poisonPatterns = [
        /ignore\s+(previous|prior|above)\s+instructions/i,
        /you\s+(must|should|are required to)\s+/i,
        /system\s*:\s*/i,
        /\<\!--.*?--\>/s,
        /​|‌|‍|﻿/,
        /override\s+(any|all)\s+/i,
        /do\s+not\s+(tell|inform|reveal)/i,
        /secretly\s+/i,
        /hidden\s+instruction/i,
      ];

      for (const pattern of poisonPatterns) {
        if (pattern.test(rawContent)) {
          findings.push(finding(
            ruleRef('MCP01-001', 'MCP01:ToolPoisoning', 'critical'),
            `Potential tool poisoning detected: content matches pattern ${pattern.source}`,
            {
              evidence: rawContent.substring(0, 200),
              remediation: 'Review tool descriptions for hidden instructions. Remove any content that attempts to override agent behavior.',
            }
          ));
        }
      }
      return findings;
    },
  },

  // MCP02: Excessive Permissions
  {
    id: 'MCP02-001',
    name: 'Overly broad file system access',
    category: 'MCP02:ExcessivePermissions',
    severity: 'high',
    description: 'Detects MCP servers with unrestricted file system access',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const args = config.args?.join(' ') ?? '';
      const cmd = config.command ?? '';

      if (args.includes('/') && !args.includes('/tmp') && !args.includes('/home')) {
        if (args.match(/\s\/\s/) || args.match(/["']\/?["']/)) {
          findings.push(finding(
            ruleRef('MCP02-001', 'MCP02:ExcessivePermissions', 'high'),
            `Server "${name}" may have root-level file system access`,
            {
              evidence: `command: ${cmd} ${args}`,
              remediation: 'Restrict file system access to the minimum required directories.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP02: Wildcard permissions
  {
    id: 'MCP02-002',
    name: 'Wildcard or star permissions',
    category: 'MCP02:ExcessivePermissions',
    severity: 'medium',
    description: 'Detects wildcard patterns that grant overly broad access',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
      ];

      for (const val of allValues) {
        if (val === '*' || val.includes(':*') || val.includes('=*') || val.match(/\*\.\*/)) {
          findings.push(finding(
            ruleRef('MCP02-002', 'MCP02:ExcessivePermissions', 'medium'),
            `Server "${name}" uses wildcard permissions: "${val}"`,
            {
              evidence: `value: ${val}`,
              remediation: 'Replace wildcards with specific resource names or patterns.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP03: Insecure Transport
  {
    id: 'MCP03-001',
    name: 'Unencrypted HTTP transport',
    category: 'MCP03:InsecureTransport',
    severity: 'high',
    description: 'Detects MCP servers using unencrypted HTTP connections',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const url = config.url ?? '';

      if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
        findings.push(finding(
          ruleRef('MCP03-001', 'MCP03:InsecureTransport', 'high'),
          `Server "${name}" uses unencrypted HTTP transport`,
          {
            evidence: `url: ${url}`,
            remediation: 'Use HTTPS for all non-localhost MCP server connections.',
          }
        ));
      }

      return findings;
    },
  },

  // MCP03: SSRF via internal/metadata URLs
  {
    id: 'MCP03-002',
    name: 'Potential SSRF via internal network URLs',
    category: 'MCP03:InsecureTransport',
    severity: 'high',
    description: 'Detects MCP servers pointing to internal or cloud metadata endpoints',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        config.url ?? '',
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
      ];

      const ssrfPatterns = [
        /169\.254\.169\.254/,
        /metadata\.google\.internal/,
        /100\.100\.100\.200/,
        /0x7f/i,
        /0177\.0/,
        /2130706433/,
      ];

      for (const val of allValues) {
        for (const pattern of ssrfPatterns) {
          if (pattern.test(val)) {
            findings.push(finding(
              ruleRef('MCP03-002', 'MCP03:InsecureTransport', 'high'),
              `Server "${name}" references internal/metadata endpoint`,
              {
                evidence: `value: ${val.substring(0, 120)}`,
                remediation: 'Do not point MCP servers at cloud metadata endpoints or internal network addresses.',
              }
            ));
            break;
          }
        }
      }

      return findings;
    },
  },

  // MCP04: Command Injection
  {
    id: 'MCP04-001',
    name: 'Shell metacharacters in server args',
    category: 'MCP04:CommandInjection',
    severity: 'critical',
    description: 'Detects potential command injection via shell metacharacters in server arguments',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const dangerous = /[;&|`$(){}]/;

      for (const arg of config.args ?? []) {
        if (dangerous.test(arg)) {
          findings.push(finding(
            ruleRef('MCP04-001', 'MCP04:CommandInjection', 'critical'),
            `Server "${name}" has shell metacharacters in args: "${arg}"`,
            {
              evidence: `arg: ${arg}`,
              remediation: 'Remove shell metacharacters from MCP server arguments. Use arrays instead of shell strings.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP05: Path Traversal
  {
    id: 'MCP05-001',
    name: 'Path traversal patterns in configuration',
    category: 'MCP05:PathTraversal',
    severity: 'high',
    description: 'Detects path traversal attempts in MCP server configuration',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        config.command ?? '',
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
      ];

      for (const val of allValues) {
        if (val.includes('..') && (val.includes('/') || val.includes('\\'))) {
          findings.push(finding(
            ruleRef('MCP05-001', 'MCP05:PathTraversal', 'high'),
            `Server "${name}" config contains path traversal pattern`,
            {
              evidence: `value: ${val}`,
              remediation: 'Use absolute paths. Never allow ".." in server configuration values.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP06: Secret Exposure
  {
    id: 'MCP06-001',
    name: 'Hardcoded secrets in configuration',
    category: 'MCP06:SecretExposure',
    severity: 'critical',
    description: 'Detects API keys, tokens, and passwords hardcoded in MCP server config',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const secretPatterns = [
        { pattern: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI API key' },
        { pattern: /ghp_[a-zA-Z0-9]{36,}/, label: 'GitHub personal access token' },
        { pattern: /glpat-[a-zA-Z0-9_-]{20,}/, label: 'GitLab personal access token' },
        { pattern: /xox[bsapr]-[a-zA-Z0-9-]+/, label: 'Slack token' },
        { pattern: /AKIA[0-9A-Z]{16}/, label: 'AWS access key' },
        { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, label: 'JWT token' },
        { pattern: /Bearer\s+[a-zA-Z0-9_.-]+/, label: 'Bearer token' },
        { pattern: /gho_[a-zA-Z0-9]{36,}/, label: 'GitHub OAuth token' },
        { pattern: /github_pat_[a-zA-Z0-9_]{22,}/, label: 'GitHub fine-grained PAT' },
        { pattern: /npm_[a-zA-Z0-9]{36,}/, label: 'npm access token' },
        { pattern: /AIza[a-zA-Z0-9_-]{35}/, label: 'Google API key' },
        { pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, label: 'SendGrid API key' },
        { pattern: /sk_live_[a-zA-Z0-9]{24,}/, label: 'Stripe secret key' },
        { pattern: /rk_live_[a-zA-Z0-9]{24,}/, label: 'Stripe restricted key' },
        { pattern: /sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}/, label: 'Square access token' },
      ];

      const allValues = [
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
        config.url ?? '',
      ];

      for (const val of allValues) {
        for (const { pattern, label } of secretPatterns) {
          if (pattern.test(val)) {
            const masked = val.replace(pattern, `[REDACTED ${label}]`);
            findings.push(finding(
              ruleRef('MCP06-001', 'MCP06:SecretExposure', 'critical'),
              `Server "${name}" has hardcoded ${label}`,
              {
                evidence: `Masked: ${masked}`,
                remediation: 'Use environment variables or a secrets manager instead of hardcoding credentials.',
              }
            ));
          }
        }
      }

      return findings;
    },
  },

  // MCP06: Sensitive env vars with literal values
  {
    id: 'MCP06-002',
    name: 'Sensitive environment variables forwarded to server',
    category: 'MCP06:SecretExposure',
    severity: 'high',
    description: 'Detects when sensitive environment variables are passed with literal values',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const sensitiveKeys = [
        /password/i, /secret/i, /private.?key/i,
        /api.?key/i, /access.?token/i, /auth.?token/i,
        /credentials/i, /connection.?string/i,
      ];

      for (const [key, val] of Object.entries(config.env ?? {})) {
        const isLiteral = !val.startsWith('${') && !val.startsWith('$');
        if (isLiteral && sensitiveKeys.some(p => p.test(key))) {
          findings.push(finding(
            ruleRef('MCP06-002', 'MCP06:SecretExposure', 'high'),
            `Server "${name}" has hardcoded value for sensitive env var "${key}"`,
            {
              evidence: `env.${key} = [REDACTED]`,
              remediation: 'Use variable references like ${ENV_VAR} or a secrets manager instead of literal values.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP07: Insecure Defaults
  {
    id: 'MCP07-001',
    name: 'Server running with insecure defaults',
    category: 'MCP07:InsecureDefaults',
    severity: 'medium',
    description: 'Detects MCP servers running without explicit security configuration',
    check: (name, config) => {
      const findings: ScanFinding[] = [];

      if (!config.transport && !config.url && config.command) {
        if (config.command.includes('ssh') || config.command.includes('docker')) {
          findings.push(finding(
            ruleRef('MCP07-001', 'MCP07:InsecureDefaults', 'medium'),
            `Server "${name}" uses remote execution without explicit transport config`,
            {
              remediation: 'Explicitly configure transport and security settings for remote MCP servers.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP08: Input Validation
  {
    id: 'MCP08-001',
    name: 'Dangerous command patterns',
    category: 'MCP08:InputValidation',
    severity: 'high',
    description: 'Detects MCP servers running dangerous commands without input validation',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const cmd = config.command ?? '';
      const dangerousCmds = ['eval', 'exec', 'sh', 'bash', 'powershell', 'cmd.exe'];

      if (dangerousCmds.some(d => cmd.endsWith(d) || cmd.includes(`/${d}`) || cmd.includes(`\\${d}`))) {
        findings.push(finding(
          ruleRef('MCP08-001', 'MCP08:InputValidation', 'high'),
          `Server "${name}" runs a shell interpreter directly: ${cmd}`,
          {
            evidence: `command: ${cmd}`,
            remediation: 'Avoid using shell interpreters as MCP server commands. Use specific, purpose-built executables.',
          }
        ));
      }

      return findings;
    },
  },

  // MCP08: Pipe to shell (curl|sh, wget|bash)
  {
    id: 'MCP08-002',
    name: 'Remote code execution via pipe-to-shell',
    category: 'MCP08:InputValidation',
    severity: 'critical',
    description: 'Detects curl|sh, wget|bash, and similar remote execution patterns',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        config.command ?? '',
        ...(config.args ?? []),
      ];
      const combined = allValues.join(' ');

      const pipeShell = /curl\s+.*\|\s*(sh|bash|zsh|fish)/i;
      const wgetShell = /wget\s+.*\|\s*(sh|bash|zsh|fish)/i;

      if (pipeShell.test(combined) || wgetShell.test(combined)) {
        findings.push(finding(
          ruleRef('MCP08-002', 'MCP08:InputValidation', 'critical'),
          `Server "${name}" downloads and executes remote code`,
          {
            evidence: combined.substring(0, 200),
            remediation: 'Never pipe remote content directly to a shell. Download, verify, then execute.',
          }
        ));
      }

      return findings;
    },
  },

  // MCP04: Template injection via server args
  {
    id: 'MCP04-002',
    name: 'Template injection patterns in arguments',
    category: 'MCP04:CommandInjection',
    severity: 'high',
    description: 'Detects template injection patterns (Jinja, EJS, Python format strings) in server arguments',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const templatePatterns = [
        /\{\{.*\}\}/,          // Jinja/Mustache/Handlebars
        /<%.*%>/,              // EJS/ERB
        /\$\{.*\}/,            // JS template literal in args (not env var refs)
        /#\{.*\}/,             // Ruby interpolation
        /\{%.*%\}/,            // Jinja block tags
      ];

      for (const arg of config.args ?? []) {
        for (const pattern of templatePatterns) {
          if (pattern.test(arg)) {
            findings.push(finding(
              ruleRef('MCP04-002', 'MCP04:CommandInjection', 'high'),
              `Server "${name}" has template injection pattern in args: "${arg.substring(0, 80)}"`,
              {
                evidence: `arg: ${arg.substring(0, 120)}`,
                remediation: 'Do not use template expressions in MCP server arguments. Use static values or environment variables.',
              }
            ));
                   break;
          }
        }
      }

      return findings;
    },
  },

  // MCP05: Sensitive file path access
  {
    id: 'MCP05-002',
    name: 'Access to sensitive system paths',
    category: 'MCP05:PathTraversal',
    severity: 'high',
    description: 'Detects MCP servers with access to sensitive system files or directories',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const sensitivePaths = [
        /\/etc\/(passwd|shadow|sudoers|ssh)/,
        /\/root\//,
        /\/\.ssh\//,
        /\/\.aws\//,
        /\/\.gnupg\//,
        /\/\.kube\/config/,
        /\/\.docker\/config/,
        /\/\.npmrc/,
        /\/\.env/,
        /\/\.git\/config/,
        /C:\\Windows\\System32/i,
        /C:\\Users\\.*\\AppData/i,
      ];

      const allValues = [
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
        config.url ?? '',
      ];

      for (const val of allValues) {
        for (const pattern of sensitivePaths) {
          if (pattern.test(val)) {
            findings.push(finding(
              ruleRef('MCP05-002', 'MCP05:PathTraversal', 'high'),
              `Server "${name}" accesses sensitive path: ${val.substring(0, 100)}`,
              {
                evidence: `value: ${val.substring(0, 120)}`,
                remediation: 'Avoid granting MCP servers access to sensitive system paths, credential stores, or config directories.',
              }
            ));
            break;
          }
        }
      }

      return findings;
    },
  },

  // MCP07: Docker socket exposure
  {
    id: 'MCP07-002',
    name: 'Docker socket or container runtime exposure',
    category: 'MCP07:InsecureDefaults',
    severity: 'critical',
    description: 'Detects MCP servers with access to Docker socket or container runtime',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        config.command ?? '',
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
      ];
      const combined = allValues.join(' ');

      if (combined.includes('/var/run/docker.sock') || combined.includes('docker.sock')) {
        findings.push(finding(
          ruleRef('MCP07-002', 'MCP07:InsecureDefaults', 'critical'),
          `Server "${name}" has access to Docker socket`,
          {
            evidence: 'docker.sock mount detected',
            remediation: 'Never expose the Docker socket to MCP servers. Use a restricted Docker API proxy if container access is needed.',
          }
        ));
      }

      return findings;
    },
  },

  // MCP10: Writable mount to host system
  {
    id: 'MCP10-002',
    name: 'Writable host mount in container config',
    category: 'MCP10:PrivilegeEscalation',
    severity: 'high',
    description: 'Detects container configs that mount host directories as writable',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const args = config.args?.join(' ') ?? '';

      // Docker -v or --volume with rw or no read-only flag on system paths
      const volumeMount = /-v\s+\/[^:]+:[^:]+(?::rw)?(?:\s|$)/;
      const bindMount = /--mount\s+type=bind[^-]*source=\/[^,]+/;

      if (volumeMount.test(args) || bindMount.test(args)) {
        // Check if mounting sensitive host paths
        const sensitiveMount = /(-v|--volume)\s+\/(etc|root|var|usr|home)[\/:\s]/;
        if (sensitiveMount.test(args)) {
          findings.push(finding(
            ruleRef('MCP10-002', 'MCP10:PrivilegeEscalation', 'high'),
            `Server "${name}" mounts host system paths into container`,
            {
              evidence: args.substring(0, 200),
              remediation: 'Avoid mounting host system directories into MCP server containers. Use named volumes or restrict to specific safe paths.',
            }
          ));
        }
      }

      return findings;
    },
  },

  // MCP09: Audit Gaps
  {
    id: 'MCP09-001',
    name: 'No audit configuration detected',
    category: 'MCP09:AuditGaps',
    severity: 'medium',
    description: 'No logging or audit trail configured for MCP tool calls',
    check: (_name, _config, _rawContent) => {
      return [];
    },
  },

  // MCP10: Privilege Escalation
  {
    id: 'MCP10-001',
    name: 'Elevated privileges in server command',
    category: 'MCP10:PrivilegeEscalation',
    severity: 'critical',
    description: 'Detects MCP servers running with elevated privileges',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const cmd = config.command ?? '';
      const args = config.args?.join(' ') ?? '';
      const combined = `${cmd} ${args}`;

      if (combined.includes('sudo') || combined.includes('--privileged') || combined.includes('as administrator')) {
        findings.push(finding(
          ruleRef('MCP10-001', 'MCP10:PrivilegeEscalation', 'critical'),
          `Server "${name}" runs with elevated privileges`,
          {
            evidence: combined.substring(0, 200),
            remediation: 'Run MCP servers with the minimum required privileges. Never use sudo or --privileged.',
          }
        ));
      }

      return findings;
    },
  },
];
