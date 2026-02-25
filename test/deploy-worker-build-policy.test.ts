import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { resolveSkipServiceBuildIfPresent } = __testing;

describe('service image build precheck policy', () => {
  it('defaults to disabled when env var is unset', () => {
    expect(resolveSkipServiceBuildIfPresent({} as NodeJS.ProcessEnv)).toBe(false);
  });

  it('enables legacy tag-only precheck when explicitly set to 1', () => {
    expect(resolveSkipServiceBuildIfPresent({
      MZ_DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT: '1',
    } as NodeJS.ProcessEnv)).toBe(true);
  });

  it('disables precheck when explicitly set to 0', () => {
    expect(resolveSkipServiceBuildIfPresent({
      MZ_DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT: '0',
    } as NodeJS.ProcessEnv)).toBe(false);
  });

  it('preserves historical non-zero semantics for compatibility', () => {
    expect(resolveSkipServiceBuildIfPresent({
      MZ_DEPLOY_SKIP_SERVICE_BUILD_IF_PRESENT: 'true',
    } as NodeJS.ProcessEnv)).toBe(true);
  });
});
