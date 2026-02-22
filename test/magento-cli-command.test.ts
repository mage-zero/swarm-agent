import { describe, expect, it } from 'vitest';
import { buildMagentoCliCommand, buildSetupDbStatusCommand } from '../src/lib/magento-cli.js';

describe('Magento CLI deploy command builders', () => {
  it('forces unlimited PHP memory for Magento CLI commands', () => {
    expect(buildMagentoCliCommand('setup:db:status'))
      .toBe('php -d memory_limit=-1 bin/magento setup:db:status');
    expect(buildMagentoCliCommand('setup:upgrade --keep-generated'))
      .toBe('php -d memory_limit=-1 bin/magento setup:upgrade --keep-generated');
    expect(buildMagentoCliCommand('app:config:import --no-interaction'))
      .toBe('php -d memory_limit=-1 bin/magento app:config:import --no-interaction');
  });

  it('builds setup:db:status command with timeout wrapper', () => {
    const command = buildSetupDbStatusCommand(120);
    expect(command).toContain('if command -v timeout >/dev/null 2>&1; then');
    expect(command).toContain('timeout 120 php -d memory_limit=-1 bin/magento setup:db:status;');
    expect(command).toContain('else');
    expect(command).toContain('php -d memory_limit=-1 bin/magento setup:db:status;');
    expect(command).toContain('fi');
  });
});
