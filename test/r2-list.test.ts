import { describe, expect, it } from 'vitest';
import { parseListObjectsV2Xml } from '../src/r2-list.js';

describe('parseListObjectsV2Xml', () => {
  it('parses keys and last modified from ListObjectsV2 response', () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <IsTruncated>false</IsTruncated>
        <Contents>
          <Key>builds/mage-zero/web-presence/build-a.tar.zst</Key>
          <LastModified>2026-02-01T00:00:00.000Z</LastModified>
        </Contents>
        <Contents>
          <Key>builds/mage-zero/web-presence/build-b.tar.zst</Key>
          <LastModified>2026-02-02T00:00:00.000Z</LastModified>
        </Contents>
      </ListBucketResult>`;

    const parsed = parseListObjectsV2Xml(xml);
    expect(parsed.isTruncated).toBe(false);
    expect(parsed.nextContinuationToken).toBeNull();
    expect(parsed.objects).toEqual([
      { key: 'builds/mage-zero/web-presence/build-a.tar.zst', lastModified: '2026-02-01T00:00:00.000Z' },
      { key: 'builds/mage-zero/web-presence/build-b.tar.zst', lastModified: '2026-02-02T00:00:00.000Z' },
    ]);
  });

  it('parses truncation and continuation token', () => {
    const xml = `
      <ListBucketResult>
        <IsTruncated>true</IsTruncated>
        <NextContinuationToken>abc123</NextContinuationToken>
        <Contents>
          <Key>k</Key>
          <LastModified>2026-02-01T00:00:00.000Z</LastModified>
        </Contents>
      </ListBucketResult>
    `;
    const parsed = parseListObjectsV2Xml(xml);
    expect(parsed.isTruncated).toBe(true);
    expect(parsed.nextContinuationToken).toBe('abc123');
    expect(parsed.objects.length).toBe(1);
  });
});

