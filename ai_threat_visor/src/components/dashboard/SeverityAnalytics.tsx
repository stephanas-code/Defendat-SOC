import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { NetworkAlert } from '../../types';

interface AnalyticsProps {
  alerts: NetworkAlert[];
}

export function SeverityAnalytics({ alerts }: AnalyticsProps) {
  const isDdos = (t: string) => /ddos|dos|hulk|loit|slowloris|goldeneye|flood/i.test(t);
  const isWeb = (t: string) => /sql|xss|traversal|command|waf|web|exploit/i.test(t);
  const isBrute = (t: string) => /brute|patator|ssh|ftp|auth/i.test(t);
  const isScan = (t: string) => /scan|recon|bot_scanner/i.test(t);
  const isK8sOrHost = (t: string) => /k8s|host|priv|rbac|secret|container|file_modified/i.test(t);

  const attackData = [
    { name: 'DDoS/DoS', count: alerts.filter(a => isDdos(a.attackType)).length, color: '#EF4444' },
    { name: 'Web/WAF', count: alerts.filter(a => isWeb(a.attackType)).length, color: '#8B5CF6' },
    { name: 'BruteForce', count: alerts.filter(a => isBrute(a.attackType)).length, color: '#F59E0B' },
    { name: 'PortScan', count: alerts.filter(a => isScan(a.attackType)).length, color: '#10B981' },
    { name: 'K8s/Host', count: alerts.filter(a => isK8sOrHost(a.attackType)).length, color: '#3B82F6' },
    {
      name: 'Zero-Day/Bot',
      count: alerts.filter(
        a =>
          a.attackType !== 'Normal' &&
          !isDdos(a.attackType) &&
          !isWeb(a.attackType) &&
          !isBrute(a.attackType) &&
          !isScan(a.attackType) &&
          !isK8sOrHost(a.attackType)
      ).length,
      color: '#06B6D4',
    },
  ];

  const severityData = [
    { name: 'Critical', value: alerts.filter(a => a.severity === 'Critical').length, color: '#EF4444' },
    { name: 'High', value: alerts.filter(a => a.severity === 'High').length, color: '#F97316' },
    { name: 'Medium', value: alerts.filter(a => a.severity === 'Medium').length, color: '#EAB308' },
    { name: 'Low', value: alerts.filter(a => a.severity === 'Low').length, color: '#3B82F6' },
  ].filter(d => d.value > 0);

  // Top attacking IPs & Most Targeted Ports
  const ipCounts: Record<string, number> = {};
  const portCounts: Record<string, number> = {};
  for (const a of alerts) {
    if (a.sourceIp) ipCounts[a.sourceIp] = (ipCounts[a.sourceIp] || 0) + 1;
    if (a.port) portCounts[`Port ${a.port} (${a.protocol})`] = (portCounts[`Port ${a.port} (${a.protocol})`] || 0) + 1;
  }
  const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-6">Attack Vectors (AI + WAF + K8s + Host)</h3>
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attackData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: '#1e293b' }}
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {attackData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-6">Severity Distribution</h3>
          <div className="h-[250px] w-full flex items-center justify-center relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData.length > 0 ? severityData : [{ name: 'None', value: 1, color: '#1e293b' }]}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {(severityData.length > 0 ? severityData : [{ name: 'None', value: 1, color: '#1e293b' }]).map(
                    (entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    )
                  )}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute flex flex-col items-center">
              <span className="text-2xl font-bold text-white">{alerts.length}</span>
              <span className="text-[10px] text-slate-500 uppercase">Total Alerts</span>
            </div>
          </div>
        </div>
      </div>

      {/* Top Attacking IPs and Most Targeted Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Top Attacking Source IPs</h4>
          {topIps.length === 0 ? (
            <p className="text-xs text-slate-500 font-mono">No attacking source IPs recorded yet.</p>
          ) : (
            <div className="space-y-2">
              {topIps.map(([ip, cnt]) => (
                <div key={ip} className="flex items-center justify-between text-xs bg-slate-950/60 px-3 py-2 rounded-lg border border-slate-800/80">
                  <span className="font-mono text-slate-200 font-bold">{ip}</span>
                  <span className="font-mono text-red-400 font-bold">{cnt} alerts</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">Most Targeted Services & Ports</h4>
          {topPorts.length === 0 ? (
            <p className="text-xs text-slate-500 font-mono">No targeted ports recorded yet.</p>
          ) : (
            <div className="space-y-2">
              {topPorts.map(([portLabel, cnt]) => (
                <div key={portLabel} className="flex items-center justify-between text-xs bg-slate-950/60 px-3 py-2 rounded-lg border border-slate-800/80">
                  <span className="font-mono text-slate-200 font-bold">{portLabel}</span>
                  <span className="font-mono text-orange-400 font-bold">{cnt} hits</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
