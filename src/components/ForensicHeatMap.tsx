import React, { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import { AlertTriangle, CheckCircle2, Clock, Sparkles, X } from 'lucide-react';
import type { AuditEvent } from '../types/forensic';

interface ForensicHeatMapProps {
  auditLogs: AuditEvent[];
  token: string;
}

type HeatmapLens = 'temporal' | 'object-actor';
type MetricMode = 'risk-anomaly' | 'tx-volume';
type TimestampBasis = 'recorded' | 'business';

interface CellBucket {
  key: string;
  xKey: string;
  yKey: string;
  label: string;
  events: AuditEvent[];
  criticalCount: number;
  warningCount: number;
  nominalCount: number;
  txAmountSum: number;
  riskScore: number;
  backdatedCount: number;
  zScore: number;
}

interface TooltipState {
  bucket: CellBucket;
  clientX: number;
  clientY: number;
}

const OFF_HOURS_SET = new Set(['00', '01', '02', '03', '04', '05']);

function formatUsdCompact(value: number): string {
  if (value >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `$${(value / 1_000).toFixed(1)}k`;
  return `$${value.toFixed(0)}`;
}

export const ForensicHeatMap: React.FC<ForensicHeatMapProps> = ({ auditLogs, token }) => {
  const [lens, setLens] = useState<HeatmapLens>('temporal');
  const [metricMode, setMetricMode] = useState<MetricMode>('risk-anomaly');
  const [timestampBasis, setTimestampBasis] = useState<TimestampBasis>('recorded');
  const [selectedCellKey, setSelectedCellKey] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);

  const [aiInsight, setAiInsight] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const legendSvgRef = useRef<SVGSVGElement | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(960);

  // Track responsive container width cleanly
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const updateWidth = () => {
      const next = el.clientWidth;
      if (next > 0) setContainerWidth(next);
    };
    updateWidth();
    const observer = new ResizeObserver(updateWidth);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Build D3 matrix buckets + Z-score temporal burst & volume statistics
  const matrixData = useMemo(() => {
    const buckets = new Map<string, CellBucket>();
    const rowSet = new Set<string>();
    const colCounts = new Map<string, number>();
    const rowCounts = new Map<string, number>();

    let totalBackdatedEvents = 0;
    let totalCriticalEvents = 0;
    let offHoursCriticalEvents = 0;

    for (const evt of auditLogs) {
      const rawTs = timestampBasis === 'recorded' ? evt.recordedAtUtc || evt.timestampUtc : evt.timestampUtc;
      const d = new Date(rawTs);
      if (Number.isNaN(d.getTime())) continue;

      const bizMs = Date.parse(evt.timestampUtc);
      const recMs = Date.parse(evt.recordedAtUtc || evt.timestampUtc);
      const isBackdatedOrSkewed = !Number.isNaN(bizMs) && !Number.isNaN(recMs) && Math.abs(recMs - bizMs) > 60_000;
      if (isBackdatedOrSkewed) totalBackdatedEvents++;

      const recDate = new Date(evt.recordedAtUtc || evt.timestampUtc);
      const recHour = String(recDate.getUTCHours()).padStart(2, '0');
      if (evt.severity === 'Critical') {
        totalCriticalEvents++;
        if (OFF_HOURS_SET.has(recHour)) offHoursCriticalEvents++;
      }

      const dateStr = d.toISOString().slice(0, 10);
      const hourStr = String(d.getUTCHours()).padStart(2, '0');

      const xKey = lens === 'temporal' ? hourStr : (evt.actor || 'unknown').split('@')[0];
      const yKey = lens === 'temporal' ? dateStr : evt.targetObject || 'unknown';
      const key = `${yKey}__${xKey}`;
      const label =
        lens === 'temporal'
          ? `${dateStr} ${hourStr}:00–${hourStr}:59 UTC (${timestampBasis === 'recorded' ? 'WAL' : 'Biz'})`
          : `${yKey} · ${xKey}`;

      rowSet.add(yKey);
      colCounts.set(xKey, (colCounts.get(xKey) || 0) + 1);
      rowCounts.set(yKey, (rowCounts.get(yKey) || 0) + 1);

      const existing = buckets.get(key) || {
        key,
        xKey,
        yKey,
        label,
        events: [],
        criticalCount: 0,
        warningCount: 0,
        nominalCount: 0,
        txAmountSum: 0,
        riskScore: 0,
        backdatedCount: 0,
        zScore: 0,
      };

      existing.events.push(evt);
      if (evt.severity === 'Critical') existing.criticalCount++;
      else if (evt.severity === 'Warning') existing.warningCount++;
      else existing.nominalCount++;

      if (typeof evt.amount === 'number' && Number.isFinite(evt.amount)) {
        existing.txAmountSum += evt.amount;
      }
      if (isBackdatedOrSkewed) existing.backdatedCount++;

      const offHoursBoost = lens === 'temporal' && OFF_HOURS_SET.has(hourStr) ? 1.5 : 0;
      existing.riskScore =
        existing.criticalCount * 5 +
        existing.warningCount * 2.5 +
        existing.nominalCount * 0.6 +
        existing.backdatedCount * 2 +
        (existing.criticalCount + existing.warningCount > 0 ? offHoursBoost : 0);

      buckets.set(key, existing);
    }

    const xKeys =
      lens === 'temporal'
        ? Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'))
        : Array.from(colCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([k]) => k);

    const yKeys =
      lens === 'temporal'
        ? Array.from(rowSet).sort()
        : Array.from(rowCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([k]) => k);

    // Compute D3 statistical mean & standard deviation across grid slots for z-score burst detection
    const slotCounts: number[] = [];
    for (const y of yKeys) {
      for (const x of xKeys) {
        const b = buckets.get(`${y}__${x}`);
        slotCounts.push(b ? b.events.length : 0);
      }
    }
    const meanCount = d3.mean(slotCounts) ?? 0;
    const stdCount = d3.deviation(slotCounts) ?? 0;

    let peakVolumeBucket: CellBucket | null = null;
    let anomalousBurstCount = 0;

    for (const bucket of buckets.values()) {
      bucket.zScore = stdCount > 0 ? (bucket.events.length - meanCount) / stdCount : 0;
      if (bucket.zScore >= 1.5 || (bucket.criticalCount > 0 && OFF_HOURS_SET.has(bucket.xKey))) {
        anomalousBurstCount++;
      }
      if (
        !peakVolumeBucket ||
        bucket.txAmountSum > peakVolumeBucket.txAmountSum ||
        (bucket.txAmountSum === peakVolumeBucket.txAmountSum &&
          bucket.events.length > peakVolumeBucket.events.length)
      ) {
        peakVolumeBucket = bucket;
      }
    }

    const maxMetricVal =
      metricMode === 'tx-volume'
        ? Math.max(
            1,
            d3.max(Array.from(buckets.values()), (b) => b.txAmountSum || b.events.length * 1000) ?? 1
          )
        : Math.max(5, d3.max(Array.from(buckets.values()), (b) => b.riskScore) ?? 5);

    const offHoursCriticalPct =
      totalCriticalEvents > 0 ? Math.round((offHoursCriticalEvents / totalCriticalEvents) * 100) : 0;

    return {
      xKeys,
      yKeys,
      buckets,
      maxMetricVal,
      peakVolumeBucket,
      anomalousBurstCount,
      totalBackdatedEvents,
      offHoursCriticalPct,
    };
  }, [auditLogs, lens, metricMode, timestampBasis]);

  const selectedBucket = selectedCellKey ? matrixData.buckets.get(selectedCellKey) || null : null;

  // Render D3 SVG Heatmap + Axes + Off-Hours Anomaly Zone
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const svg = d3.select<SVGSVGElement, unknown>(svgEl);
    svg.selectAll('*').remove();

    const { xKeys, yKeys, buckets, maxMetricVal } = matrixData;
    if (xKeys.length === 0 || yKeys.length === 0) return;

    const minCanvasWidth = lens === 'temporal' ? 780 : 700;
    const width = Math.max(containerWidth, minCanvasWidth);
    const margin = {
      top: 42,
      right: 20,
      bottom: 18,
      left: lens === 'temporal' ? 112 : 196,
    };
    const rowHeight = lens === 'temporal' ? 36 : 42;
    const innerWidth = Math.max(300, width - margin.left - margin.right);
    const innerHeight = Math.max(80, yKeys.length * rowHeight);
    const totalHeight = margin.top + innerHeight + margin.bottom;

    svg
      .attr('viewBox', `0 0 ${width} ${totalHeight}`)
      .attr('width', width)
      .attr('height', totalHeight);

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);

    const xScale = d3
      .scaleBand<string>()
      .domain(xKeys)
      .range([0, innerWidth])
      .padding(0.12);

    const yScale = d3
      .scaleBand<string>()
      .domain(yKeys)
      .range([0, innerHeight])
      .padding(0.16);

    const volumeColorScale = d3
      .scaleSequential(d3.interpolateBlues)
      .domain([0, maxMetricVal]);

    const riskColorScale = d3
      .scaleSequential(d3.interpolateYlOrRd)
      .domain([0, maxMetricVal]);

    // Highlight Off-Hours Risk Band (00:00-05:59 UTC) on temporal lens
    if (lens === 'temporal') {
      const startX = xScale('00');
      const endX = xScale('05');
      if (startX !== undefined && endX !== undefined) {
        const bandWidth = endX + xScale.bandwidth() - startX;
        g.append('rect')
          .attr('x', startX - 4)
          .attr('y', -22)
          .attr('width', bandWidth + 8)
          .attr('height', innerHeight + 28)
          .attr('rx', 4)
          .attr('fill', '#FEF2F2')
          .attr('stroke', '#FCA5A5')
          .attr('stroke-dasharray', '3,3')
          .attr('stroke-width', 1);

        g.append('text')
          .attr('x', startX + bandWidth / 2)
          .attr('y', -28)
          .attr('text-anchor', 'middle')
          .attr('fill', '#B91C1C')
          .style('font-family', '"JetBrains Mono", monospace')
          .style('font-size', '10px')
          .style('font-weight', '600')
          .text('Off-Hours Anomaly Window (00–05 UTC)');
      }
    }

    // X Axis (Top)
    const xAxis = d3.axisTop(xScale).tickSize(0);
    const xAxisG = g.append('g').call(xAxis);
    xAxisG.select('.domain').remove();
    xAxisG
      .selectAll<SVGTextElement, string>('text')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', '11px')
      .attr('dy', '-4')
      .attr('fill', (d) =>
        lens === 'temporal' && OFF_HOURS_SET.has(d) ? '#B91C1C' : '#475569'
      )
      .style('font-weight', (d) =>
        lens === 'temporal' && OFF_HOURS_SET.has(d) ? '600' : '500'
      )
      .text((d) => (d.length > 13 ? `${d.slice(0, 12)}…` : d));

    // Y Axis (Left)
    const yAxis = d3.axisLeft(yScale).tickSize(0);
    const yAxisG = g.append('g').call(yAxis);
    yAxisG.select('.domain').remove();
    yAxisG
      .selectAll<SVGTextElement, string>('text')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', '11px')
      .attr('dx', '-6')
      .attr('fill', '#1E293B')
      .text((d) => (d.length > 24 ? `${d.slice(0, 23)}…` : d));

    // Flatten grid cells for D3 data join
    interface GridDatum {
      key: string;
      xKey: string;
      yKey: string;
      bucket: CellBucket | undefined;
    }

    const cells: GridDatum[] = [];
    for (const yKey of yKeys) {
      for (const xKey of xKeys) {
        const key = `${yKey}__${xKey}`;
        cells.push({
          key,
          xKey,
          yKey,
          bucket: buckets.get(key),
        });
      }
    }

    const cellFill = (d: GridDatum): string => {
      if (!d.bucket || d.bucket.events.length === 0) return '#F8FAFC';
      if (metricMode === 'tx-volume') {
        const val = d.bucket.txAmountSum > 0 ? d.bucket.txAmountSum : d.bucket.events.length * 1000;
        const normalized = Math.max(maxMetricVal * 0.16, val);
        return volumeColorScale(normalized);
      }
      if (d.bucket.criticalCount === 0 && d.bucket.warningCount === 0) {
        return d.bucket.events.length >= 2 ? '#DBEAFE' : '#EFF6FF';
      }
      const normalizedRisk = Math.max(maxMetricVal * 0.25, d.bucket.riskScore);
      return riskColorScale(normalizedRisk);
    };

    const cellStroke = (d: GridDatum): string => {
      if (selectedCellKey === d.key) return '#0F172A';
      if (d.bucket && d.bucket.criticalCount > 0) return '#DC2626';
      if (d.bucket && d.bucket.warningCount > 0) return '#D97706';
      if (d.bucket && d.bucket.events.length > 0) return '#93C5FD';
      return '#E2E8F0';
    };

    const cellTextFill = (d: GridDatum): string => {
      if (!d.bucket || d.bucket.events.length === 0) return '#CBD5E1';
      if (metricMode === 'tx-volume') {
        const val = d.bucket.txAmountSum > 0 ? d.bucket.txAmountSum : d.bucket.events.length * 1000;
        return val / maxMetricVal > 0.55 ? '#FFFFFF' : '#0F172A';
      }
      if (d.bucket.criticalCount === 0 && d.bucket.warningCount === 0) return '#1E3A8A';
      return d.bucket.riskScore / maxMetricVal > 0.58 ? '#FFFFFF' : '#7F1D1D';
    };

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const cellGroups = g
      .selectAll<SVGGElement, GridDatum>('g.hm-cell')
      .data(cells, (d) => d.key)
      .join('g')
      .attr('class', 'hm-cell')
      .attr('transform', (d) => `translate(${xScale(d.xKey) ?? 0},${yScale(d.yKey) ?? 0})`)
      .style('cursor', (d) => (d.bucket ? 'pointer' : 'default'));

    const rects = cellGroups
      .append('rect')
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 3)
      .attr('fill', cellFill)
      .attr('stroke', cellStroke)
      .attr('stroke-width', (d) =>
        selectedCellKey === d.key ? 2.25 : d.bucket && d.bucket.criticalCount > 0 ? 1.4 : 1
      )
      .style('opacity', prefersReducedMotion ? 1 : 0.85);

    if (!prefersReducedMotion) {
      rects.transition().duration(180).style('opacity', 1);
    }

    // Cell count / dollar volume label
    cellGroups
      .filter((d) => Boolean(d.bucket && d.bucket.events.length > 0))
      .append('text')
      .attr('x', xScale.bandwidth() / 2)
      .attr('y', yScale.bandwidth() / 2)
      .attr('dominant-baseline', 'central')
      .attr('text-anchor', 'middle')
      .style('pointer-events', 'none')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', metricMode === 'tx-volume' && lens === 'object-actor' ? '10.5px' : '11px')
      .style('font-weight', '600')
      .attr('fill', cellTextFill)
      .text((d) => {
        if (!d.bucket) return '';
        if (metricMode === 'tx-volume' && d.bucket.txAmountSum > 0 && xScale.bandwidth() >= 46) {
          return formatUsdCompact(d.bucket.txAmountSum);
        }
        return String(d.bucket.events.length);
      });

    // Small warning/anomaly corner marker when in Transaction Volume mode so anomalies stay visible
    cellGroups
      .filter((d) => Boolean(metricMode === 'tx-volume' && d.bucket && d.bucket.criticalCount > 0))
      .append('rect')
      .attr('x', Math.max(0, xScale.bandwidth() - 7))
      .attr('y', 2)
      .attr('width', 5)
      .attr('height', 5)
      .attr('rx', 1)
      .attr('fill', '#DC2626')
      .style('pointer-events', 'none');

    // Interactive D3 mouseover, mousemove, mouseout, and click events
    cellGroups
      .on('mouseenter', function (event: MouseEvent, d: GridDatum) {
        if (!d.bucket) return;
        d3.select(this).select('rect').attr('stroke', '#0F172A').attr('stroke-width', 2);
        setTooltip({
          bucket: d.bucket,
          clientX: event.clientX,
          clientY: event.clientY,
        });
      })
      .on('mousemove', (event: MouseEvent, d: GridDatum) => {
        if (!d.bucket) return;
        setTooltip({
          bucket: d.bucket,
          clientX: event.clientX,
          clientY: event.clientY,
        });
      })
      .on('mouseleave', function (_event: MouseEvent, d: GridDatum) {
        d3.select(this)
          .select('rect')
          .attr('stroke', cellStroke(d))
          .attr('stroke-width', selectedCellKey === d.key ? 2.25 : d.bucket && d.bucket.criticalCount > 0 ? 1.4 : 1);
        setTooltip(null);
      })
      .on('click', (_event: MouseEvent, d: GridDatum) => {
        if (!d.bucket) return;
        setSelectedCellKey((prev) => (prev === d.key ? null : d.key));
      });
  }, [matrixData, lens, metricMode, containerWidth, selectedCellKey]);

  // Render D3 Continuous Gradient Scale Legend
  useEffect(() => {
    const legendEl = legendSvgRef.current;
    if (!legendEl) return;
    const svg = d3.select<SVGSVGElement, unknown>(legendEl);
    svg.selectAll('*').remove();

    const legendW = 210;
    const barH = 8;
    const gradId = `veritas-hm-grad-${metricMode}`;

    const defs = svg.append('defs');
    const grad = defs.append('linearGradient').attr('id', gradId).attr('x1', '0%').attr('x2', '100%');
    const interpolator = metricMode === 'tx-volume' ? d3.interpolateBlues : d3.interpolateYlOrRd;

    d3.range(0, 1.05, 0.1).forEach((t) => {
      grad
        .append('stop')
        .attr('offset', `${Math.round(t * 100)}%`)
        .attr('stop-color', interpolator(t));
    });

    svg
      .append('rect')
      .attr('x', 8)
      .attr('y', 4)
      .attr('width', legendW)
      .attr('height', barH)
      .attr('rx', 2)
      .attr('fill', `url(#${gradId})`)
      .attr('stroke', '#CBD5E1')
      .attr('stroke-width', 0.75);

    const scale = d3.scaleLinear().domain([0, matrixData.maxMetricVal]).range([0, legendW]);
    const axis = d3
      .axisBottom(scale)
      .ticks(3)
      .tickSize(3)
      .tickFormat((v) =>
        metricMode === 'tx-volume' ? formatUsdCompact(Number(v)) : String(Math.round(Number(v)))
      );

    const axisG = svg
      .append('g')
      .attr('transform', `translate(8,${4 + barH})`)
      .call(axis);
    axisG.select('.domain').remove();
    axisG
      .selectAll('text')
      .style('font-family', '"JetBrains Mono", monospace')
      .style('font-size', '10px')
      .attr('fill', '#64748B');
  }, [metricMode, matrixData.maxMetricVal]);

  const handleAnalyzeHotspots = async () => {
    setAiError(null);
    setAnalyzing(true);
    try {
      const topHotspots = Array.from(matrixData.buckets.values())
        .sort((a, b) => b.riskScore - a.riskScore || b.txAmountSum - a.txAmountSum)
        .slice(0, 5)
        .map((b) => ({
          label: b.label,
          totalCount: b.events.length,
          criticalCount: b.criticalCount,
          warningCount: b.warningCount,
          actions: Array.from(new Set(b.events.map((e) => e.action))),
        }));

      const res = await fetch('/api/ai/heatmap-insight', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          lens:
            lens === 'temporal'
              ? `D3 Date × Hour UTC (${timestampBasis === 'recorded' ? 'System WAL Time' : 'Business Timestamp'}, ${metricMode})`
              : `D3 RDBMS Object × Actor (${metricMode})`,
          selectedLabel: selectedBucket?.label,
          topHotspots,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAiError(data.error || 'Failed to analyze heat map concentration.');
        return;
      }
      setAiInsight(data.insight);
    } catch {
      setAiError('Network error analyzing concentration hotspots.');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
      {/* Header & Controls */}
      <div className="px-6 py-4 border-b border-slate-200 flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">
            RDBMS Transaction Volume &amp; Concentration Anomaly Heat Map
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            D3-rendered activity density and statistical burst detection across RDBMS tables, actors, and UTC windows. Click any populated cell to inspect records.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {/* Lens Selector */}
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            <button
              type="button"
              onClick={() => {
                setLens('temporal');
                setSelectedCellKey(null);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                lens === 'temporal' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Hour UTC × Date
            </button>
            <button
              type="button"
              onClick={() => {
                setLens('object-actor');
                setSelectedCellKey(null);
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                lens === 'object-actor' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Object × Actor
            </button>
          </div>

          {/* Metric Mode Selector */}
          <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
            <button
              type="button"
              onClick={() => setMetricMode('risk-anomaly')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                metricMode === 'risk-anomaly' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Anomaly Intensity
            </button>
            <button
              type="button"
              onClick={() => setMetricMode('tx-volume')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                metricMode === 'tx-volume' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Transaction Volume
            </button>
          </div>

          {/* Timestamp Basis Switch (reveals backdated vs WAL clustering) */}
          {lens === 'temporal' && (
            <div className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
              <button
                type="button"
                onClick={() => {
                  setTimestampBasis('recorded');
                  setSelectedCellKey(null);
                }}
                className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  timestampBasis === 'recorded' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                WAL Recorded
              </button>
              <button
                type="button"
                onClick={() => {
                  setTimestampBasis('business');
                  setSelectedCellKey(null);
                }}
                className={`px-2.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  timestampBasis === 'business' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Business Time
              </button>
            </div>
          )}

          <button
            type="button"
            onClick={handleAnalyzeHotspots}
            disabled={analyzing || auditLogs.length === 0}
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
          >
            <Sparkles className="w-3.5 h-3.5 text-blue-300" />
            <span>{analyzing ? 'Analyzing...' : 'AI Hotspot Insight'}</span>
          </button>
        </div>
      </div>

      <div className="p-6 space-y-5">
        {/* Statistical Concentration & Volume Cluster Strip */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pb-4 border-b border-slate-200 text-xs">
          <div>
            <div className="text-slate-500">Peak Transaction Volume Cluster</div>
            <div className="mt-1 font-mono tabular-nums font-semibold text-slate-900">
              {matrixData.peakVolumeBucket
                ? `${matrixData.peakVolumeBucket.label.split(' (')[0]} · $${matrixData.peakVolumeBucket.txAmountSum.toLocaleString(undefined, { maximumFractionDigits: 0 })}`
                : 'No volume data'}
            </div>
          </div>

          <div>
            <div className="text-slate-500">Off-Hours Critical Concentration (00–05 UTC)</div>
            <div className="mt-1 font-mono tabular-nums font-semibold text-red-700">
              {matrixData.offHoursCriticalPct}% of critical events · {matrixData.anomalousBurstCount} z-score burst cell(s)
            </div>
          </div>

          <div>
            <div className="text-slate-500">Backdated / Business-vs-WAL Skew</div>
            <div className="mt-1 font-mono tabular-nums font-semibold text-amber-700 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 shrink-0" />
              <span>
                {matrixData.totalBackdatedEvents} event(s) shifted between WAL &amp; Business time
              </span>
            </div>
          </div>
        </div>

        {/* D3 Continuous Scale Legend + Discrete State Indicators */}
        <div className="flex flex-wrap items-center justify-between gap-4 text-[11px] text-slate-600">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="w-3.5 h-3.5 rounded-xs bg-slate-50 border border-slate-200 inline-block" />
              <span>0 events</span>
            </div>
            {metricMode === 'risk-anomaly' ? (
              <>
                <div className="flex items-center gap-1.5">
                  <span className="w-3.5 h-3.5 rounded-xs bg-blue-50 border border-blue-300 inline-block" />
                  <span>Nominal only</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3.5 h-3.5 rounded-xs bg-amber-300 border border-amber-500 inline-block" />
                  <span>Warning / skew</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-3.5 h-3.5 rounded-xs bg-red-600 border border-red-700 inline-block" />
                  <span>Critical cluster</span>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-xs bg-red-600 inline-block" />
                <span>Red corner marker = Critical anomaly present</span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-500">
              {metricMode === 'tx-volume' ? 'USD Volume Scale:' : 'Risk Weight Scale:'}
            </span>
            <svg
              ref={legendSvgRef}
              width={228}
              height={30}
              aria-label="D3 heatmap color scale legend"
            />
          </div>
        </div>

        {/* D3 SVG Canvas */}
        {auditLogs.length === 0 ? (
          <div className="py-12 text-center text-sm text-slate-500 border border-slate-200 rounded-md bg-slate-50">
            No audit events loaded yet. Run a holistic scan or ingest a database backup to populate transaction clusters.
          </div>
        ) : (
          <div ref={containerRef} className="w-full overflow-x-auto">
            <svg
              ref={svgRef}
              className="block select-none"
              role="img"
              aria-label="D3 RDBMS transaction volume and time-based anomaly concentration heatmap"
            />
          </div>
        )}

        {/* D3 Floating Hover Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 pointer-events-none bg-slate-900 text-white rounded-md shadow-lg px-3.5 py-2.5 text-xs max-w-xs border border-slate-700"
            style={{
              left: Math.min(tooltip.clientX + 14, (typeof window !== 'undefined' ? window.innerWidth : 1200) - 270),
              top: Math.max(12, tooltip.clientY - 12),
            }}
          >
            <div className="font-mono font-semibold text-blue-300">{tooltip.bucket.label}</div>
            <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1 font-mono tabular-nums text-[11px]">
              <span className="text-slate-400">Events:</span>
              <span className="text-right font-semibold">{tooltip.bucket.events.length}</span>
              <span className="text-slate-400">TXN Volume:</span>
              <span className="text-right font-semibold">
                ${tooltip.bucket.txAmountSum.toLocaleString(undefined, { minimumFractionDigits: 2 })}
              </span>
              <span className="text-slate-400">Critical / Warn:</span>
              <span className="text-right">
                {tooltip.bucket.criticalCount} / {tooltip.bucket.warningCount}
              </span>
              <span className="text-slate-400">Burst Z-Score:</span>
              <span className="text-right">
                {tooltip.bucket.zScore >= 0 ? `+${tooltip.bucket.zScore.toFixed(2)}` : tooltip.bucket.zScore.toFixed(2)}σ
              </span>
            </div>
            {tooltip.bucket.backdatedCount > 0 && (
              <div className="mt-1.5 pt-1.5 border-t border-slate-700 text-[11px] text-amber-300">
                Includes {tooltip.bucket.backdatedCount} backdated / skewed timestamp record(s)
              </div>
            )}
          </div>
        )}

        {/* AI Hotspot Interpretation Banner */}
        {aiError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md flex items-start gap-2 text-xs text-red-800">
            <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <span>{aiError}</span>
          </div>
        )}

        {aiInsight && (
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-md text-xs text-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 font-semibold text-slate-900">
                <Sparkles className="w-3.5 h-3.5 text-blue-700" />
                <span>Gemini AI Concentration Analysis</span>
              </div>
              <button
                type="button"
                onClick={() => setAiInsight(null)}
                className="text-slate-400 hover:text-slate-700"
                aria-label="Dismiss AI insight"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="whitespace-pre-wrap leading-relaxed text-slate-700">{aiInsight}</div>
          </div>
        )}

        {/* Selected Cell Drilldown */}
        {selectedBucket && (
          <div className="border border-slate-200 rounded-md overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="font-semibold text-slate-900">
                Cluster Drilldown: <span className="font-mono">{selectedBucket.label}</span>
                <span className="text-slate-400 font-normal mx-1.5">·</span>
                <span className="font-mono tabular-nums font-normal text-slate-700">
                  {selectedBucket.events.length} event(s) · ${selectedBucket.txAmountSum.toLocaleString(undefined, { minimumFractionDigits: 2 })}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedCellKey(null)}
                className="text-slate-500 hover:text-slate-800"
              >
                Clear Selection
              </button>
            </div>
            <div className="divide-y divide-slate-200">
              {selectedBucket.events.map((evt) => (
                <div
                  key={evt.id}
                  className="px-4 py-3 text-xs flex flex-col lg:flex-row lg:items-center justify-between gap-2"
                >
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      {evt.severity === 'Critical' ? (
                        <AlertTriangle className="w-3.5 h-3.5 text-red-700 shrink-0" />
                      ) : evt.severity === 'Warning' ? (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                      )}
                      <span className="font-mono text-slate-500">#{evt.sequenceId}</span>
                      <span className="font-semibold text-slate-900">{evt.action}</span>
                      <span className="text-slate-400">·</span>
                      <span className="font-mono text-slate-700">{evt.targetObject}</span>
                      {typeof evt.amount === 'number' && (
                        <>
                          <span className="text-slate-400">·</span>
                          <span className="font-mono tabular-nums font-semibold text-slate-900">
                            ${evt.amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}
                          </span>
                        </>
                      )}
                    </div>
                    <div className="mt-1 text-slate-600">
                      Actor: <span className="font-mono">{evt.actor}</span>
                      {evt.transactionCode ? ` · TXN: ${evt.transactionCode}` : ''}
                      {evt.anomalyFlags.length > 0 ? ` · Flags: ${evt.anomalyFlags.join(', ')}` : ''}
                    </div>
                  </div>
                  <div className="font-mono tabular-nums text-[11px] text-slate-500 shrink-0 text-left lg:text-right">
                    <div>WAL: {evt.recordedAtUtc}</div>
                    {evt.timestampUtc !== evt.recordedAtUtc && (
                      <div className="text-amber-700">Biz: {evt.timestampUtc}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
