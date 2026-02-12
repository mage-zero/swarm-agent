import path from 'path';

export type CommandPolicyMode = 'off' | 'audit' | 'enforce';

export type CommandPolicyContext = {
  source?: string;
};

type Decision =
  | { allowed: true }
  | { allowed: false; reason: string };

function getModeFromEnv(): CommandPolicyMode {
  const raw = String(process.env.MZ_COMMAND_POLICY_MODE || '').trim().toLowerCase();
  if (raw === 'off' || raw === '0' || raw === 'false') return 'off';
  if (raw === 'audit') return 'audit';
  if (raw === 'enforce') return 'enforce';
  // Default to enforce so we fail-closed on unexpected command execution.
  return 'enforce';
}

function baseCommand(command: string) {
  // We generally pass plain binaries (e.g. "docker"), but be defensive.
  return path.basename(command || '');
}

function hasUnsafeArgChars(value: string) {
  // NUL/newlines are almost always a bug in argv construction.
  return value.includes('\u0000') || value.includes('\n') || value.includes('\r');
}

function deny(reason: string): Decision {
  return { allowed: false, reason };
}

function allow(): Decision {
  return { allowed: true };
}

function isAllowed(command: string, args: string[]): Decision {
  const cmd = baseCommand(command);
  if (!cmd) return deny('empty command');

  for (const arg of args) {
    if (hasUnsafeArgChars(arg)) return deny('argv contains unsafe characters');
  }

  // Keep this intentionally tight. Add to this list as new functionality is introduced.
  switch (cmd) {
    case 'docker': {
      const sub = String(args[0] || '');
      const allowedSubs = new Set([
        'service',
        'stack',
        'secret',
        'image',
        'system',
        'builder',
        'run',
        'network',
        'node',
        'volume',
        'exec',
        'cp',
        'load',
        'tag',
        'push',
      ]);
      if (!allowedSubs.has(sub)) return deny(`docker subcommand not allowlisted: ${sub || '(missing)'}`);
      return allow();
    }
    case 'curl': {
      // We use curl for artifact fetches and a few internal registry operations.
      // Disallow payload-bearing flags by default.
      const disallowed = new Set(['--data', '--data-raw', '--data-binary', '-d', '--form', '-F', '--upload-file']);
      for (const arg of args) {
        if (disallowed.has(arg)) return deny(`curl flag not allowlisted: ${arg}`);
      }
      return allow();
    }
    case 'git': {
      // Only allow the subset we currently use (clone/fetch/checkout).
      const sub = String(args[0] || '');
      const allowed = new Set(['clone', 'fetch', 'checkout', '-C']);
      if (!allowed.has(sub)) return deny(`git invocation not allowlisted: ${sub || '(missing)'}`);
      return allow();
    }
    case 'tar': {
      // Currently used for extracting build archives.
      return allow();
    }
    case 'zstd': {
      return allow();
    }
    case 'age': {
      return allow();
    }
    case 'df': {
      // Used by diagnostics runbooks.
      return allow();
    }
    case 'bash': {
      // We intentionally do not allow interactive shell execution.
      // Permit a small, explicit set of script files and block `bash -lc ...`.
      if (args[0] === '-lc') return deny('bash -lc is not allowlisted');
      if (args.length < 1) return deny('bash must be invoked with a script path');
      const scriptPath = args[0] || '';
      if (!path.isAbsolute(scriptPath)) return deny('bash script path must be absolute');
      if (scriptPath.endsWith('/scripts/registry-gc.sh')) {
        if (args.length !== 1) return deny('registry-gc.sh does not accept extra args');
        return allow();
      }
      if (scriptPath.endsWith('/scripts/build-services.sh')) {
        if (args.length !== 1) return deny('build-services.sh does not accept extra args');
        return allow();
      }
      if (scriptPath.endsWith('/scripts/build-magento.sh')) {
        if (args.length < 2) return deny('build-magento.sh requires artifact path arg');
        return allow();
      }
      return deny('bash script is not allowlisted');
    }
    default:
      return deny(`command not allowlisted: ${cmd}`);
  }
}

export function enforceCommandPolicy(command: string, args: string[], context: CommandPolicyContext = {}) {
  const mode = getModeFromEnv();
  if (mode === 'off') return;

  const decision = isAllowed(command, args);
  if (decision.allowed) return;

  const message = [
    'command policy violation',
    context.source ? `source=${context.source}` : '',
    `command=${baseCommand(command)}`,
    `args=${JSON.stringify(args)}`,
    `reason=${decision.reason}`,
  ]
    .filter(Boolean)
    .join(' ');

  if (mode === 'enforce') {
    throw new Error(message);
  }

  // audit
  console.warn(message);
}
