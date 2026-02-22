export function buildMagentoCliCommand(args: string): string {
  return `php -d memory_limit=-1 bin/magento ${args}`.trim();
}

export function buildSetupDbStatusCommand(timeoutSeconds: number): string {
  const dbStatusCommand = buildMagentoCliCommand('setup:db:status');
  return [
    'if command -v timeout >/dev/null 2>&1; then',
    `timeout ${timeoutSeconds} ${dbStatusCommand};`,
    'else',
    `${dbStatusCommand};`,
    'fi',
  ].join(' ');
}
