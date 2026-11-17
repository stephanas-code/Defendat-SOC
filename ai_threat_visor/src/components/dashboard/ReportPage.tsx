import { FileText, Download, TrendingUp } from 'lucide-react';
import { DashboardStats, NetworkAlert } from '../../types';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import { cn } from '../../lib/utils';

interface ReportPageProps {
  alerts: NetworkAlert[];
  stats?: DashboardStats;
}

const PALETTE = ['#3B82F6', '#EF4444', '#F59E0B', '#10B981', '#8B5CF6', '#06B6D4', '#EC4899'];

export function ReportPage({ alerts, stats }: ReportPageProps) {
  const activeAlerts = alerts.filter(
    (a) => a.attackType && !['normal', 'benign', '0'].includes(a.attackType.toLowerCase())
  );

  const hasAlerts = activeAlerts.length > 0;

  const reportData = Array.from(new Set(activeAlerts.map((a) => a.attackType))).map((type, idx) => ({
    name: type,
    count: activeAlerts.filter((a) => a.attackType === type).length,
    color: PALETTE[idx % PALETTE.length],
  }));

  const criticalCount = activeAlerts.filter((a) => a.severity === 'Critical').length;
  const highCount = activeAlerts.filter((a) => a.severity === 'High').length;
  const mediumCount = activeAlerts.filter((a) => a.severity === 'Medium').length;

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
  } else if (activeAlerts.length > 0) {
    avgSeverity = 'LOW RISK';
    severityColorClass = 'text-blue-400 font-bold';
  }

  const avgConfidencePct =
    activeAlerts.length > 0
      ? `${((activeAlerts.reduce((acc, a) => acc + (a.confidence || 0), 0) / activeAlerts.length) * 100).toFixed(1)}%`
      : 'N/A';

  let topAttackLocation = 'N/A';
  let topAttackType = 'N/A';
  if (activeAlerts.length > 0) {
    const locations = activeAlerts.reduce((acc, curr) => {
      acc[curr.location ?? 'Unknown'] = (acc[curr.location ?? 'Unknown'] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    topAttackLocation = Object.entries(locations).sort((a, b) => b[1] - a[1])[0][0];

    const types = activeAlerts.reduce((acc, curr) => {
      acc[curr.attackType] = (acc[curr.attackType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    topAttackType = Object.entries(types).sort((a, b) => b[1] - a[1])[0][0];
  }

  const reportDescription =
    activeAlerts.length > 0
      ? `Live telemetry indicates active threat patterns (${topAttackType}) originating from ${topAttackLocation}.`
      : 'No anomalous flows or attacks recorded in the current database window.';

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify({ generated_at: new Date().toISOString(), stats, alerts: activeAlerts }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai-ids-idp-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
            <FileText className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Analytics Reports</h2>
            <p className="text-slate-400 text-sm font-medium">Consolidated security intelligence from live database records</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-bold shadow-lg shadow-blue-900/20 transition-all cursor-pointer"
          >
            <Download className="w-4 h-4" /> Export Telemetry JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-8">
          <div className="flex items-center justify-between mb-10">
            <div>
              <h3 className="text-lg font-bold text-white">Detected Incursion Distribution</h3>
              <p className="text-xs text-slate-500">Attack classification by live database count</p>
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
              <p className="text-sm font-bold text-slate-300 mb-1">No Anomalies Recorded</p>
              <p className="text-xs text-slate-500 max-w-sm">
                Database currently contains zero alerts. Real-time detections from the network sensor, host monitor, Kubernetes audit, and WAF will populate here automatically.
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
                <span className="text-sm text-slate-400 font-medium">Total Alerts</span>
                <span className="text-sm font-black text-white font-mono">{activeAlerts.length.toLocaleString()}</span>
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
