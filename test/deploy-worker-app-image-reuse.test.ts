import { describe, expect, it } from 'vitest';
import { __testing } from '../src/deploy-worker.js';

const { shouldReuseAppImagesForCloudSwarmRef } = __testing;

describe('app image reuse policy', () => {
  it('allows reuse when the current cloud-swarm ref is unavailable', () => {
    expect(shouldReuseAppImagesForCloudSwarmRef(null, {
      magento: 'older-ref',
      nginxApp: 'older-ref',
    })).toBe(true);
  });

  it('allows reuse when both app images match the current cloud-swarm ref', () => {
    expect(shouldReuseAppImagesForCloudSwarmRef('abc123', {
      magento: 'abc123',
      nginxApp: 'abc123',
    })).toBe(true);
  });

  it('forces rebuild when the magento image was built from an older cloud-swarm ref', () => {
    expect(shouldReuseAppImagesForCloudSwarmRef('new-ref', {
      magento: 'old-ref',
      nginxApp: 'new-ref',
    })).toBe(false);
  });

  it('forces rebuild when the nginx image is missing the cloud-swarm ref label', () => {
    expect(shouldReuseAppImagesForCloudSwarmRef('new-ref', {
      magento: 'new-ref',
      nginxApp: null,
    })).toBe(false);
  });
});
