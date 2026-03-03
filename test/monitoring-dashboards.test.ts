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

  it('includes a dedicated varnish dashboard and access visualizations', () => {
    const objects = __testing.buildSavedObjects();
    const dashboard = objects.find((object) => object.type === 'dashboard' && object.id === 'mz-dashboard-varnish');
    const statusTrend = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-varnish-status-trend');
    const hitRateTrend = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-varnish-hit-rate-trend');

    expect(dashboard).toBeTruthy();
    expect(statusTrend).toBeTruthy();
    expect(hitRateTrend).toBeTruthy();
    expect(dashboard?.attributes?.title).toBe('3) Varnish');
  });

  it('restores useful default time ranges for shared dashboards', () => {
    const objects = __testing.buildSavedObjects();
    const ops = objects.find((object) => object.type === 'dashboard' && object.id === 'mz-dashboard-ops');
    const containers = objects.find((object) => object.type === 'dashboard' && object.id === 'mz-dashboard-magento-containers');
    const varnish = objects.find((object) => object.type === 'dashboard' && object.id === 'mz-dashboard-varnish');

    expect(ops?.attributes?.timeRestore).toBe(true);
    expect(ops?.attributes?.timeFrom).toBe('now-24h');
    expect(ops?.attributes?.timeTo).toBe('now');
    expect(containers?.attributes?.timeRestore).toBe(true);
    expect(containers?.attributes?.timeFrom).toBe('now-24h');
    expect(containers?.attributes?.timeTo).toBe('now');
    expect(varnish?.attributes?.timeRestore).toBe(true);
    expect(varnish?.attributes?.timeFrom).toBe('now-7d');
    expect(varnish?.attributes?.timeTo).toBe('now');
  });

  it('uses dashboard-context placeholders in varnish Vega queries', () => {
    const objects = __testing.buildSavedObjects();
    const statusTrend = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-varnish-status-trend');
    const spec = JSON.parse(
      String((JSON.parse(String(statusTrend?.attributes?.visState || '{}'))?.params?.spec) || '{}'),
    ) as Record<string, unknown>;

    const data = (spec.data && typeof spec.data === 'object') ? (spec.data as Record<string, unknown>) : {};
    const url = (data.url && typeof data.url === 'object') ? (data.url as Record<string, unknown>) : {};
    const body = (url.body && typeof url.body === 'object') ? (url.body as Record<string, unknown>) : {};
    const query = (body.query && typeof body.query === 'object') ? (body.query as Record<string, unknown>) : {};
    const bool = (query.bool && typeof query.bool === 'object') ? (query.bool as Record<string, unknown>) : {};
    const must = Array.isArray(bool.must) ? bool.must : [];
    const filter = Array.isArray(bool.filter) ? bool.filter : [];
    const mustNot = Array.isArray(bool.must_not) ? bool.must_not : [];

    expect(url['%context%']).toBeUndefined();
    expect(url['%timefield%']).toBeUndefined();
    expect(must).toContain('%dashboard_context-must_clause%');
    expect(filter).toContain('%dashboard_context-filter_clause%');
    expect(mustNot).toContain('%dashboard_context-must_not_clause%');
    expect(JSON.stringify(must)).toContain('%timefilter%');
    expect(JSON.stringify(must)).toContain('varnish.access');
  });

  it('uses the corrected CPU dataset and preserves zero values in container CPU charts', () => {
    const objects = __testing.buildSavedObjects();
    const cpuByService = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-container-cpu-by-service');
    const cpuTrend = objects.find((object) => object.type === 'visualization' && object.id === 'mz-vis-container-cpu-trend');

    const cpuByServiceSpec = JSON.parse(
      String((JSON.parse(String(cpuByService?.attributes?.visState || '{}'))?.params?.spec) || '{}'),
    ) as Record<string, unknown>;
    const cpuTrendSpec = JSON.parse(
      String((JSON.parse(String(cpuTrend?.attributes?.visState || '{}'))?.params?.spec) || '{}'),
    ) as Record<string, unknown>;

    const byServiceMust = (((((cpuByServiceSpec.data as Record<string, unknown>)?.url as Record<string, unknown>)?.body as Record<string, unknown>)?.aggs as Record<string, unknown>)?.filtered as Record<string, unknown>)?.filter as Record<string, unknown>;
    const trendMust = (((((cpuTrendSpec.data as Record<string, unknown>)?.url as Record<string, unknown>)?.body as Record<string, unknown>)?.aggs as Record<string, unknown>)?.filtered as Record<string, unknown>)?.filter as Record<string, unknown>;
    const byServiceTransform = Array.isArray(cpuByServiceSpec.transform) ? cpuByServiceSpec.transform : [];
    const trendTransform = Array.isArray(cpuTrendSpec.transform) ? cpuTrendSpec.transform : [];

    expect(JSON.stringify(byServiceMust)).toContain('mz.docker.cpu');
    expect(JSON.stringify(trendMust)).toContain('mz.docker.cpu');
    expect(JSON.stringify(byServiceTransform)).toContain('isValid(datum.cpu_avg)');
    expect(JSON.stringify(trendTransform)).toContain('isValid(datum.point.cpu_avg)');
  });
});
