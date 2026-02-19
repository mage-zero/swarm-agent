import { describe, expect, it } from 'vitest';
import { __testing } from '../src/monitoring-dashboards.js';

describe('monitoring-dashboards helpers', () => {
  it('does not pin VPS root trend color scale to fixed host domain/range', () => {
    const objects = __testing.buildSavedObjects();
    const rootTrend = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-vps-root-trend');
    expect(rootTrend).toBeTruthy();

    const visState = JSON.parse(String(rootTrend?.attributes?.visState || '{}')) as Record<string, unknown>;
    const params = (visState.params && typeof visState.params === 'object')
      ? (visState.params as Record<string, unknown>)
      : {};
    const spec = JSON.parse(String(params.spec || '{}')) as Record<string, unknown>;
    const encoding = (spec.encoding && typeof spec.encoding === 'object')
      ? (spec.encoding as Record<string, unknown>)
      : {};
    const color = (encoding.color && typeof encoding.color === 'object')
      ? (encoding.color as Record<string, unknown>)
      : {};
    const scale = (color.scale && typeof color.scale === 'object')
      ? (color.scale as Record<string, unknown>)
      : {};

    expect(color.field).toBe('host_label');
    expect(scale.domain).toBeUndefined();
    expect(scale.range).toBeUndefined();
  });

  it('parses dashboard API output status and JSON payload', () => {
    const parsed = __testing.parseDashboardsApiOutput('{"status":{"overall":{"state":"green"}}}\n200');
    expect(parsed.status).toBe(200);
    expect(parsed.body).toContain('"green"');
    expect(parsed.parsed).toEqual({ status: { overall: { state: 'green' } } });
  });

  it('treats yellow state as ready and 503 as not ready', () => {
    expect(__testing.isDashboardsReady({
      status: 200,
      body: '{"status":{"overall":{"state":"yellow"}}}',
      parsed: { status: { overall: { state: 'yellow' } } },
    })).toBe(true);

    expect(__testing.isDashboardsReady({
      status: 503,
      body: '{"status":{"overall":{"state":"red"}}}',
      parsed: { status: { overall: { state: 'red' } } },
    })).toBe(false);
  });
});
