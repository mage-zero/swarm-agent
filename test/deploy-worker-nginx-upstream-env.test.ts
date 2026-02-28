import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { buildNginxPhpUpstreamEnv } = __testing;

describe('nginx php upstream env', () => {
  it('routes frontend and admin FastCGI traffic to service task DNS', () => {
    expect(buildNginxPhpUpstreamEnv()).toEqual({
      MZ_PHP_FPM_HOST: 'tasks.php-fpm',
      MZ_PHP_FPM_ADMIN_HOST: 'tasks.php-fpm-admin',
    });
  });
});
