import React, { useMemo, useState } from 'react';
import { FileText, Download, Filter, TrendingUp, Calendar, X, RotateCcw } from 'lucide-react';
import { DashboardStats, NetworkAlert } from '../../types';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { toast } from 'sonner';
import { cn } from '../../lib/utils';

interface ReportPageProps {
  alerts: NetworkAlert[];
  stats?: DashboardStats;
}

type TimeRangePreset = 'all' | '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';
type SeverityFilter = 'all' | 'critical' | 'high_critical' | 'medium_up';

const PALETTE = ['#3B82F6', '#EF4444', '#F59E0B', '#10B981', '#8B5CF6', '#06B6D4', '#EC4899'];

const RANGE_LABELS: Record<TimeRangePreset, string> = {
  all: 'All Time',
  '1h': 'Last 1 Hour',
  '6h': 'Last 6 Hours',
  '24h': 'Last 24 Hours',
  '7d': 'Last 7 Days',
  '30d': 'Last 30 Days',
  custom: 'Custom Date Range',
};

function escapePdfText(str: string): string {
  return str
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

/**
 * Generates a standards-compliant PDF 1.4 binary document containing the
 * Executive Summary, Infrastructure State, Attack Breakdown, and Alert Log.
 */
function generateSecurityReportPdf(params: {
  rangeLabel: string;
  severityFilter: string;
  avgSeverity: string;
  avgConfidencePct: string;
  totalFiltered: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  topAttackType: string;
  topAttackLocation: string;
  reportData: Array<{ name: string; count: number }>;
  alerts: NetworkAlert[];
  stats?: DashboardStats;
}): Blob {
  const lines: Array<{ text: string; size: number; bold?: boolean; indent?: number }> = [];
  const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  lines.push({ text: 'DEFENDAT SOC - SECURITY INTELLIGENCE REPORT', size: 16, bold: true });
  lines.push({ text: `Generated: ${nowStr}   |   Filter Range: ${params.rangeLabel} (${params.severityFilter.toUpperCase()})`, size: 9 });
  lines.push({ text: 'Researcher: Stephanas Osanebi Odogu   |   Supervisor: Dr. Oluwasegun I. Adelaiye   |   MIVA Open University', size: 9 });
  lines.push({ text: '----------------------------------------------------------------------------------------------------', size: 9 });

  lines.push({ text: '1. EXECUTIVE SUMMARY', size: 12, bold: true });
  lines.push({ text: `Overall Risk Posture     : ${params.avgSeverity}`, size: 10, indent: 12 });
  lines.push({ text: `Total Alerts in Range    : ${params.totalFiltered}`, size: 10, indent: 12 });
  lines.push({
    text: `Severity Breakdown       : Critical: ${params.criticalCount}  |  High: ${params.highCount}  |  Medium: ${params.mediumCount}  |  Low: ${params.lowCount}`,
    size: 10,
    indent: 12,
  });
  lines.push({ text: `Mean AI Model Confidence : ${params.avgConfidencePct}`, size: 10, indent: 12 });
  lines.push({ text: `Primary Attack Vector    : ${params.topAttackType}`, size: 10, indent: 12 });
  lines.push({ text: `Primary Origin Location  : ${params.topAttackLocation}`, size: 10, indent: 12 });
  lines.push({ text: '', size: 8 });

  lines.push({ text: '2. LIVE INFRASTRUCTURE & PREVENTION TELEMETRY', size: 12, bold: true });
  lines.push({ text: `Total Network Flows Analyzed : ${(params.stats?.flowsTotal ?? 0).toLocaleString()}`, size: 10, indent: 12 });
  lines.push({ text: `Active IDP Firewall Blocks   : ${params.stats?.infrastructure?.idpActiveBlocks ?? 0}`, size: 10, indent: 12 });
  lines.push({ text: `IDP Enforcement Mode         : ${params.stats?.infrastructure?.idpMode ?? 'safe_enforce'}`, size: 10, indent: 12 });
  lines.push({ text: `Open Correlated Incidents    : ${params.stats?.infrastructure?.incidentsOpen ?? 0}`, size: 10, indent: 12 });
  lines.push({ text: `WAF Threats Blocked / Caught : ${params.stats?.infrastructure?.wafBlocked ?? 0} / ${params.stats?.infrastructure?.wafDetected ?? 0}`, size: 10, indent: 12 });
  lines.push({ text: `Host CPU / RAM Utilization   : ${params.stats?.infrastructure?.cpuLoadPct ?? 0}% CPU  |  ${params.stats?.infrastructure?.memoryUsedPct ?? 0}% RAM`, size: 10, indent: 12 });
  lines.push({ text: '', size: 8 });

  lines.push({ text: '3. ATTACK CLASSIFICATION DISTRIBUTION', size: 12, bold: true });
  if (params.reportData.length === 0) {
    lines.push({ text: 'No attack classifications recorded in the selected filter range.', size: 10, indent: 12 });
  } else {
    for (const item of params.reportData) {
      lines.push({
        text: `${item.name.padEnd(32, ' ')} : ${String(item.count).padStart(5, ' ')} alerts`,
        size: 10,
        indent: 12,
      });
    }
  }
  lines.push({ text: '', size: 8 });

  lines.push({ text: '4. CHRONOLOGICAL SECURITY ALERT LOG (TOP 100 IN RANGE)', size: 12, bold: true });
  lines.push({
    text: 'TIMESTAMP (UTC)      | SEV      | ATTACK CLASSIFICATION    | SOURCE IP -> TARGET        | CONF',
    size: 9,
    bold: true,
  });
  lines.push({ text: '----------------------------------------------------------------------------------------------------', size: 9 });

  if (params.alerts.length === 0) {
    lines.push({ text: 'No security alerts matched the selected filter criteria.', size: 9, indent: 12 });
  } else {
    for (const a of params.alerts.slice(0, 100)) {
      const ts = new Date(a.timestamp).toISOString().replace('T', ' ').slice(0, 19);
      const sev = (a.severity || 'Low').toUpperCase().padEnd(8, ' ').slice(0, 8);
      const cls = (a.attackType || 'Unknown').padEnd(24, ' ').slice(0, 24);
      const flow = `${a.sourceIp} -> ${a.destIp}:${a.port}`.padEnd(26, ' ').slice(0, 26);
      const conf = `${((a.confidence || 0) * 100).toFixed(0)}%`;
      lines.push({ text: `${ts} | ${sev} | ${cls} | ${flow} | ${conf}`, size: 8.5 });
    }
  }

  // Paginate lines (approx 46 lines per page)
  const LINES_PER_PAGE = 46;
  const pages: Array<typeof lines> = [];
  for (let i = 0; i < lines.length; i += LINES_PER_PAGE) {
    pages.push(lines.slice(i, i + LINES_PER_PAGE));
  }
  if (pages.length === 0) pages.push([]);

  // Build PDF objects:
  // 1: Catalog, 2: Pages, 3: Font Regular (Courier), 4: Font Bold (Courier-Bold)
  // Then for each page: Page object + Content stream object
  const objects: string[] = [];
  objects.push('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj');

  const pageObjNumbers: number[] = [];
  let nextObjNum = 5;
  for (let p = 0; p < pages.length; p++) {
    pageObjNumbers.push(nextObjNum);
    nextObjNum += 2;
  }

  const kidsStr = pageObjNumbers.map((n) => `${n} 0 R`).join(' ');
  objects.push(`2 0 obj\n<< /Type /Pages /Kids [${kidsStr}] /Count ${pages.length} >>\nendobj`);
  objects.push('3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj');
  objects.push('4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>\nendobj');

  for (let p = 0; p < pages.length; p++) {
    const pageObjId = pageObjNumbers[p];
    const contentObjId = pageObjId + 1;
    const pageLines = pages[p];

    const streamParts: string[] = [];
    streamParts.push('BT');
    let y = 790;
    for (const ln of pageLines) {
      const fontRef = ln.bold ? '/F2' : '/F1';
      const x = 36 + (ln.indent || 0);
      streamParts.push(`${fontRef} ${ln.size} Tf`);
      streamParts.push(`1 0 0 1 ${x} ${y} Tm`);
      streamParts.push(`(${escapePdfText(ln.text)}) Tj`);
      y -= ln.size + 6;
    }
    // Page footer
    streamParts.push('/F1 8 Tf');
    streamParts.push(`1 0 0 1 36 24 Tm`);
    streamParts.push(`(Page ${p + 1} of ${pages.length}  -  AI Anomaly IDS/IDP Security Report) Tj`);
    streamParts.push('ET');

    const streamContent = streamParts.join('\n');
    objects.push(
      `${pageObjId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjId} 0 R >>\nendobj`
    );
    objects.push(
      `${contentObjId} 0 obj\n<< /Length ${streamContent.length} >>\nstream\n${streamContent}\nendstream\nendobj`
    );
  }

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [0];
  for (const obj of objects) {
    offsets.push(pdf.length);
    pdf += obj + '\n';
  }
  const xrefStart = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;

  return new Blob([pdf], { type: 'application/pdf' });
}

export function ReportPage({ alerts, stats }: ReportPageProps) {
  const [showFilterPanel, setShowFilterPanel] = useState(false);
  const [rangePreset, setRangePreset] = useState<TimeRangePreset>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  const [attackSearch, setAttackSearch] = useState('');

  // Filter alerts based on selected Time Range, Severity, and Search query
  const filteredAlerts = useMemo(() => {
    const now = Date.now();
    const hourMs = 3600 * 1000;
    const windowMap: Partial<Record<TimeRangePreset, number>> = {
      '1h': hourMs,
      '6h': 6 * hourMs,
      '24h': 24 * hourMs,
      '7d': 7 * 24 * hourMs,
      '30d': 30 * 24 * hourMs,
    };

    return alerts.filter((a) => {
      if (!a.attackType || ['normal', 'benign', '0'].includes(a.attackType.toLowerCase())) {
        return false;
      }

      // 1. Time range check
      const ts = Date.parse(a.timestamp);
      if (!Number.isNaN(ts)) {
        if (rangePreset === 'custom') {
          if (customStart) {
            const startMs = Date.parse(customStart);
            if (!Number.isNaN(startMs) && ts < startMs) return false;
          }
          if (customEnd) {
            const endMs = Date.parse(customEnd);
            if (!Number.isNaN(endMs) && ts > endMs) return false;
          }
        } else if (rangePreset !== 'all') {
          const maxAge = windowMap[rangePreset];
          if (maxAge && now - ts > maxAge) return false;
        }
      }

      // 2. Severity filter check
      if (severityFilter === 'critical' && a.severity !== 'Critical') return false;
      if (severityFilter === 'high_critical' && a.severity !== 'Critical' && a.severity !== 'High') return false;
      if (severityFilter === 'medium_up' && a.severity === 'Low') return false;

      // 3. Search filter check
      if (attackSearch.trim()) {
        const q = attackSearch.trim().toLowerCase();
        const blob = `${a.attackType} ${a.sourceIp} ${a.destIp} ${a.location || ''} ${a.port}`.toLowerCase();
        if (!blob.includes(q)) return false;
      }

      return true;
    });
  }, [alerts, rangePreset, severityFilter, customStart, customEnd, attackSearch]);

  const hasAlerts = filteredAlerts.length > 0;

  const reportData = useMemo(() => {
    return Array.from(new Set(filteredAlerts.map((a) => a.attackType))).map((type, idx) => ({
      name: type,
      count: filteredAlerts.filter((a) => a.attackType === type).length,
      color: PALETTE[idx % PALETTE.length],
    }));
  }, [filteredAlerts]);

  const criticalCount = filteredAlerts.filter((a) => a.severity === 'Critical').length;
  const highCount = filteredAlerts.filter((a) => a.severity === 'High').length;
  const mediumCount = filteredAlerts.filter((a) => a.severity === 'Medium').length;
  const lowCount = filteredAlerts.filter((a) => a.severity === 'Low').length;

  let avgSeverity = 'CLEAN';
  let severityColorClass = 'text-emerald-400';
  if (criticalCount > 0) {
    avgSeverity = 'CRITICAL';
    severityColorClass = 'text-red-500 font-bold';
  } else if (highCount > 0) {
    avgSeverity = 'HIGH RISK';
    severityColorClass = 'text-orange-500 font-bold';
  } else if (mediumCount > 0) {
    avgSeverity = 'MODERATE';
    severityColorClass = 'text-yellow-500 font-bold';
  } else if (filteredAlerts.length > 0) {
    avgSeverity = 'LOW RISK';
    severityColorClass = 'text-blue-400 font-bold';
  }

  const avgConfidencePct =
    filteredAlerts.length > 0
      ? `${((filteredAlerts.reduce((acc, a) => acc + (a.confidence || 0), 0) / filteredAlerts.length) * 100).toFixed(1)}%`
      : 'N/A';

  let topAttackLocation = 'N/A';
  let topAttackType = 'N/A';
  if (filteredAlerts.length > 0) {
    const locations = filteredAlerts.reduce((acc, curr) => {
      acc[curr.location ?? 'Unresolved IP'] = (acc[curr.location ?? 'Unresolved IP'] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    topAttackLocation = Object.entries(locations).sort((a, b) => b[1] - a[1])[0][0];

    const types = filteredAlerts.reduce((acc, curr) => {
      acc[curr.attackType] = (acc[curr.attackType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    topAttackType = Object.entries(types).sort((a, b) => b[1] - a[1])[0][0];
  }

  const reportDescription =
    filteredAlerts.length > 0
      ? `Live telemetry (${RANGE_LABELS[rangePreset]}) indicates active threat patterns (${topAttackType}) originating from ${topAttackLocation}.`
      : `No anomalous flows or attacks matched the selected filter range (${RANGE_LABELS[rangePreset]}).`;

  const handleResetFilters = () => {
    setRangePreset('all');
    setSeverityFilter('all');
    setCustomStart('');
    setCustomEnd('');
    setAttackSearch('');
    toast.info('Report filters reset to All Time');
  };

  const handleExportPdf = () => {
    try {
      const pdfBlob = generateSecurityReportPdf({
        rangeLabel:
          rangePreset === 'custom'
            ? `${customStart || 'Start'} to ${customEnd || 'Now'}`
            : RANGE_LABELS[rangePreset],
        severityFilter,
        avgSeverity,
        avgConfidencePct,
        totalFiltered: filteredAlerts.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        topAttackType,
        topAttackLocation,
        reportData,
        alerts: filteredAlerts,
        stats,
      });

      const url = URL.createObjectURL(pdfBlob);
      const a = document.createElement('a');
      const dateStamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
      a.href = url;
      a.download = `Defendat-SOC-Security-Report-${dateStamp}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast.success('PDF Security Report Exported', {
        description: `Downloaded Defendat-SOC-Security-Report-${dateStamp}.pdf (${filteredAlerts.length} alerts in range).`,
      });
    } catch {
      toast.error('Failed to generate PDF report');
    }
  };

  const isFiltered = rangePreset !== 'all' || severityFilter !== 'all' || Boolean(attackSearch.trim());

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
            <FileText className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Analytics Reports</h2>
            <p className="text-slate-400 text-sm font-medium">
              Showing <span className="text-white font-mono font-bold">{filteredAlerts.length}</span> alerts for{' '}
              <span className="text-blue-400 font-semibold">{RANGE_LABELS[rangePreset]}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFilterPanel((prev) => !prev)}
            className={cn(
              'flex items-center gap-2 px-4 py-2 border rounded-lg text-sm font-semibold transition-all cursor-pointer',
              showFilterPanel || isFiltered
                ? 'bg-blue-500/15 border-blue-500/40 text-blue-400'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white'
            )}
          >
            <Filter className="w-4 h-4" />
            <span>Filter Range {isFiltered ? `(${RANGE_LABELS[rangePreset]})` : ''}</span>
          </button>
          <button
            onClick={handleExportPdf}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-bold shadow-lg shadow-blue-900/20 transition-all cursor-pointer active:scale-95"
          >
            <Download className="w-4 h-4" /> Export PDF
          </button>
        </div>
      </div>

      {/* Interactive Filter Range Panel */}
      {showFilterPanel && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 animate-in slide-in-from-top-2 duration-200">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
              <Calendar className="w-4 h-4 text-blue-400" />
              Filter Report Time Range & Severity Scope
            </div>
            <div className="flex items-center gap-2">
              {isFiltered && (
                <button
                  onClick={handleResetFilters}
                  className="flex items-center gap-1 text-xs font-mono text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-800 cursor-pointer"
                >
                  <RotateCcw className="w-3 h-3" /> Reset
                </button>
              )}
              <button
                onClick={() => setShowFilterPanel(false)}
                className="text-slate-400 hover:text-white p-1 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Preset Time Windows */}
            <div>
              <label className="text-[10px] font-bold uppercase text-slate-500 block mb-2">Time Range Window</label>
              <div className="flex flex-wrap gap-1.5">
                {(['all', '1h', '6h', '24h', '7d', '30d', 'custom'] as TimeRangePreset[]).map((preset) => (
                  <button
                    key={preset}
                    onClick={() => setRangePreset(preset)}
                    className={cn(
                      'px-2.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer border',
                      rangePreset === preset
                        ? 'bg-blue-600 text-white border-blue-500'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-white'
                    )}
                  >
                    {RANGE_LABELS[preset]}
                  </button>
                ))}
              </div>
            </div>

            {/* Severity Scope */}
            <div>
              <label className="text-[10px] font-bold uppercase text-slate-500 block mb-2">Severity Level</label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              >
                <option value="all">All Severities (Critical, High, Medium, Low)</option>
                <option value="critical">Critical Threats Only</option>
                <option value="high_critical">Critical & High Only</option>
                <option value="medium_up">Medium, High & Critical</option>
              </select>
            </div>

            {/* Attack Type / IP Filter */}
            <div>
              <label className="text-[10px] font-bold uppercase text-slate-500 block mb-2">
                Filter by Attack Type, IP, or Port
              </label>
              <input
                type="text"
                placeholder="e.g. DDoS, SQL, 185.220, 443..."
                value={attackSearch}
                onChange={(e) => setAttackSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
              />
            </div>
          </div>

          {rangePreset === 'custom' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80">
              <div>
                <label className="text-[10px] font-bold uppercase text-slate-500 block mb-1">Start Date & Time</label>
                <input
                  type="datetime-local"
                  value={customStart}
                  onChange={(e) => setCustomStart(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] font-bold uppercase text-slate-500 block mb-1">End Date & Time</label>
                <input
                  type="datetime-local"
                  value={customEnd}
                  onChange={(e) => setCustomEnd(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
                />
              </div>
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-8">
          <div className="flex items-center justify-between mb-10">
            <div>
              <h3 className="text-lg font-bold text-white">Detected Incursion Distribution</h3>
              <p className="text-xs text-slate-500">
                Attack classification for {RANGE_LABELS[rangePreset]} ({filteredAlerts.length} alerts)
              </p>
            </div>
            <div className="p-2 bg-black/40 rounded-lg border border-slate-800">
              <TrendingUp className="w-5 h-5 text-emerald-500" />
            </div>
          </div>

          {hasAlerts ? (
            <div className="h-[350px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={reportData}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip
                    cursor={{ fill: '#1e293b', radius: 4 }}
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: '12px',
                    }}
                  />
                  <Bar dataKey="count" radius={[6, 6, 0, 0]} barSize={40}>
                    {reportData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-[350px] w-full flex flex-col items-center justify-center border border-dashed border-slate-800 rounded-xl bg-slate-950/20 p-8 text-center">
              <FileText className="w-12 h-12 text-slate-700 mb-4" />
              <p className="text-sm font-bold text-slate-300 mb-1">No Anomalies in Selected Range</p>
              <p className="text-xs text-slate-500 max-w-sm">
                Zero alerts matched the current filter ({RANGE_LABELS[rangePreset]}). Adjust the Filter Range or wait for live detections.
              </p>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <h4 className="text-xs font-black text-slate-500 uppercase tracking-[0.2em] mb-6">Executive Summary</h4>
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400 font-medium">Highest Severity</span>
                <span className={cn('text-sm font-mono uppercase', severityColorClass)}>{avgSeverity}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400 font-medium">Mean Confidence</span>
                <span className="text-sm font-black text-emerald-400 font-mono">{avgConfidencePct}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400 font-medium">Filtered Alerts</span>
                <span className="text-sm font-black text-white font-mono">{filteredAlerts.length.toLocaleString()}</span>
              </div>
            </div>
            <div className="mt-8 pt-8 border-t border-slate-800">
              <p className="text-[11px] text-slate-500 leading-relaxed font-medium">{reportDescription}</p>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-slate-300">
            <h4 className="text-xs font-black text-slate-500 uppercase tracking-[0.2em] mb-6">Live Infrastructure State</h4>
            <div className="space-y-4">
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Flows Stored in DB:</span>
                <span className="font-bold text-white font-mono">{(stats?.flowsTotal ?? 0).toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Active IDP Blocks:</span>
                <span className="font-bold text-emerald-400 font-mono">{stats?.infrastructure?.idpActiveBlocks ?? 0}</span>
              </div>
              <div className="flex justify-between items-center text-xs">
                <span className="text-slate-400">Open Correlated Incidents:</span>
                <span className="font-bold text-white font-mono">{stats?.infrastructure?.incidentsOpen ?? 0}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
