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
  Pie
} from 'recharts';
import { NetworkAlert } from '../../types';

interface AnalyticsProps {
  alerts: NetworkAlert[];
}

export function SeverityAnalytics({ alerts }: AnalyticsProps) {
  const attackData = [
    { name: 'DDoS', count: alerts.filter(a => a.attackType === 'DDoS').length, color: '#3B82F6' },
    { name: 'SQLi', count: alerts.filter(a => a.attackType === 'SQL Injection').length, color: '#8B5CF6' },
    { name: 'Brute', count: alerts.filter(a => a.attackType === 'Brute Force').length, color: '#F59E0B' },
    { name: 'PortScan', count: alerts.filter(a => a.attackType === 'Port Scan').length, color: '#10B981' },
    { name: 'Other', count: alerts.filter(a => !['Normal', 'DDoS', 'SQL Injection', 'Brute Force', 'Port Scan'].includes(a.attackType)).length, color: '#64748B' },
  ];

  const severityData = [
    { name: 'Critical', value: alerts.filter(a => a.severity === 'Critical').length, color: '#EF4444' },
    { name: 'High', value: alerts.filter(a => a.severity === 'High').length, color: '#F97316' },
    { name: 'Medium', value: alerts.filter(a => a.severity === 'Medium').length, color: '#EAB308' },
    { name: 'Low', value: alerts.filter(a => a.severity === 'Low').length, color: '#3B82F6' },
  ].filter(d => d.value > 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-6">Attack Vectors (ML Classification)</h3>
        <div className="h-[250px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={attackData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis 
                dataKey="name" 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false} 
                axisLine={false} 
              />
              <YAxis 
                stroke="#64748b" 
                fontSize={10} 
                tickLine={false} 
                axisLine={false}
              />
              <Tooltip 
                cursor={{ fill: '#1e293b' }}
                contentStyle={{ 
                  backgroundColor: '#0f172a', 
                  border: '1px solid #1e293b',
                  borderRadius: '8px',
                  fontSize: '12px'
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
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#0f172a', 
                  border: '1px solid #1e293b',
                  borderRadius: '8px',
                  fontSize: '12px'
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute flex flex-col items-center">
            <span className="text-2xl font-bold text-white">{alerts.filter(a => a.severity !== 'Low').length}</span>
            <span className="text-[10px] text-slate-500 uppercase">Alerts</span>
          </div>
        </div>
      </div>
    </div>
  );
}