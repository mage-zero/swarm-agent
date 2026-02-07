export type R2ListObject = {
  key: string;
  lastModified: string;
};

export type R2ListObjectsV2Result = {
  objects: R2ListObject[];
  isTruncated: boolean;
  nextContinuationToken: string | null;
};

function decodeXmlText(value: string): string {
  // We only need enough decoding to handle common XML escaping in object keys.
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

export function parseListObjectsV2Xml(xml: string): R2ListObjectsV2Result {
  const objects: R2ListObject[] = [];
  const contentsRe = /<Contents>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<LastModified>([\s\S]*?)<\/LastModified>[\s\S]*?<\/Contents>/g;
  for (const match of xml.matchAll(contentsRe)) {
    const rawKey = match[1] ?? '';
    const rawLast = match[2] ?? '';
    const key = decodeXmlText(rawKey.trim());
    const lastModified = decodeXmlText(rawLast.trim());
    if (key) {
      objects.push({ key, lastModified });
    }
  }

  const isTruncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(xml);
  const tokenMatch = xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/i);
  const nextContinuationToken = tokenMatch ? decodeXmlText(String(tokenMatch[1] || '').trim()) : null;

  return { objects, isTruncated, nextContinuationToken: nextContinuationToken || null };
}

