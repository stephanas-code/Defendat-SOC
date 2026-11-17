import { Shield, AlertCircle, Activity, Zap, ArrowUpRight, ArrowDownRight, Server, Layers, Lock, Globe } from 'lucide-react';
import { NetworkAlert, DashboardStats } from '../../types';
import { Card } from '../ui/card';

interface StatCardsProps {
  alerts: NetworkAlert[];
  stats: DashboardStats;
}

export function StatCards({ alerts, stats }: StatCardsProps) {
  const alertsTotal = stats?.alertsTotal ?? alerts.length;
  const criticalCount = stats?.criticalTotal ?? alerts.filter(a => a.severity === 'Critical').length;

  const avgConfidence = alerts.length > 0
    ? (alerts.reduce((sum, a) => sum + (a.confidence ?? 0), 0) / alerts.length) * 100
    : 0.0;

  const flowsScanned = stats?.flowsTotal ?? 0;

  const criticalPercentage = alertsTotal > 0
    ? Math.round((criticalCount / alertsTotal) * 100)
    : 0;

  const inf = stats?.infrastructure;

  const statItems = [
    {
      label: 'Flows Analyzed',
      value: flowsScanned.toLocaleString(),
      change: inf?.idsEnabled !== false ? 'IDS Active' : 'IDS Paused',
      trend: 'up',
      progress: Math.min(100, flowsScanned > 0 ? 85 : 15),
      icon: Activity,
    },
    {
      label: 'Detected Threats',
      value: alertsTotal.toLocaleString(),
      change: `+${stats?.alertsLastHour ?? 0} last hr`,
      trend: 'up',
      progress: Math.min(100, alertsTotal > 0 ? 75 : 5),
      icon: AlertCircle,
    },
    {
      label: 'Critical & Blocked',
      value: `${criticalCount.toLocaleString()} / ${(inf?.idpActiveBlocks ?? 0).toLocaleString()}`,
      change: inf?.idpEnabled ? `IDP ${inf.idpMode.toUpperCase()}` : 'IDP Monitor Only',
      trend: criticalPercentage > 20 ? 'up' : 'down',
      progress: Math.min(100, criticalPercentage || (inf?.idpActiveBlocks ? 60 : 10)),
      icon: Shield,
    },
    {
      label: 'AI Confidence',
      value: alerts.length > 0 ? `${avgConfidence.toFixed(1)}%` : 'Ready',
      change: `${inf?.incidentsOpen ?? 0} Correlated Incidents`,
      trend: 'up',
      progress: alerts.length > 0 ? Math.min(100, Math.round(avgConfidence)) : 100,
      icon: Zap,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
        {statItems.map((stat, idx) => (
          <Card
            key={idx}
            className="bg-slate-900 border-slate-800 p-5 group hover:border-slate-700 transition-all duration-300 hover:shadow-lg hover:shadow-blue-900/5 relative overflow-hidden"
          >
            <div className="absolute -right-2 -bottom-2 p-2 opacity-5 group-hover:opacity-10 transition-opacity">
              <stat.icon className="w-24 h-24 text-white" />
            </div>

            <div className="flex items-start justify-between relative z-10">
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 group-hover:border-blue-500/50 transition-colors">
                <stat.icon className="w-5 h-5 text-blue-500" />
              </div>
              <div
                className={`flex items-center gap-1 text-[10px] font-bold px-2 py-1 rounded-full ${
                  stat.trend === 'up' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                }`}
              >
                {stat.trend === 'up' ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {stat.change}
              </div>
            </div>

            <div className="mt-4 relative z-10">
              <h3 className="text-slate-500 text-xs font-bold uppercase tracking-widest mb-1">{stat.label}</h3>
              <div className="flex items-baseline gap-2">
                <p className="text-3xl font-black text-white tracking-tight">{stat.value}</p>
              </div>
            </div>

            <div className="mt-6 w-full h-1 bg-slate-800 rounded-full overflow-hidden relative z-10">
              <div
                className="h-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)] transition-all duration-500"
                style={{ width: `${stat.progress}%` }}
              />
            </div>
          </Card>
        ))}
      </div>

      {/* Infrastructure & Multi-Layer Security Status Bar */}
      {inf && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 text-xs">
          <div className="flex items-center gap-2.5 px-2">
            <Server className="w-4 h-4 text-emerald-400 shrink-0" />
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold">Linux Host</p>
              <p className="font-mono font-bold text-white uppercase">{inf.serverStatus} ({inf.cpuLoadPct}% CPU)</p>
            </div>
          </div>
          <div className="flex items-center gap-2.5 px-2">
            <Layers className="w-4 h-4 text-blue-400 shrink-0" />
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold">K8s Cluster</p>
              <p className="font-mono font-bold text-white uppercase">{inf.clusterStatus}</p>
            </div>
          </div>
          <div className="px-2">
            <p className="text-[10px] text-slate-500 uppercase font-bold">Nodes / NS</p>
            <p className="font-mono font-bold text-white">{inf.monitoredNodes} Nodes / {inf.monitoredNamespaces} NS</p>
          </div>
          <div className="px-2">
            <p className="text-[10px] text-slate-500 uppercase font-bold">Pods / Apps</p>
            <p className="font-mono font-bold text-white">{inf.monitoredPods} Pods / {inf.monitoredApplications} Apps</p>
          </div>
          <div className="px-2">
            <p className="text-[10px] text-slate-500 uppercase font-bold">Host Sockets</p>
            <p className="font-mono font-bold text-white">{inf.activeConnections} ({inf.establishedConnections} ESTAB)</p>
          </div>
          <div className="flex items-center gap-2 px-2">
            <Lock className="w-4 h-4 text-purple-400 shrink-0" />
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold">IDP Status</p>
              <p className="font-mono font-bold text-emerald-400">{inf.idpEnabled ? `${inf.idpActiveBlocks} Blocked` : 'Disabled'}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-2">
            <Globe className="w-4 h-4 text-orange-400 shrink-0" />
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold">OWASP WAF</p>
              <p className="font-mono font-bold text-white">{inf.wafBlocked} Blocked / {inf.wafDetected} Hits</p>
            </div>
          </div>
          <div className="px-2">
            <p className="text-[10px] text-slate-500 uppercase font-bold">Host Memory</p>
            <p className="font-mono font-bold text-white">{inf.memoryUsedPct}% Used</p>
          </div>
        </div>
      )}
    </div>
  );
}
