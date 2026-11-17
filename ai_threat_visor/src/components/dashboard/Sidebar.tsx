import { Shield, Server, Database, Globe, AlertTriangle, Settings, FileText, LayoutDashboard, Lock, Layers, ShieldCheck } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isMobile?: boolean;
  engineOnline?: boolean;
}

const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard', id: 'dashboard' },
  { icon: Lock, label: 'IDP & Incidents', id: 'idp' },
  { icon: Layers, label: 'K8s, Host & WAF', id: 'k8s' },
  { icon: AlertTriangle, label: 'Live Alerts', id: 'alerts' },
  { icon: Globe, label: 'Threat Map', id: 'map' },
  { icon: Server, label: 'ML Models', id: 'models' },
  { icon: Database, label: 'Persistence', id: 'data' },
  { icon: FileText, label: 'Reports', id: 'reports' },
  { icon: Settings, label: 'Settings & Setup', id: 'settings' },
];

export function Sidebar({ activeTab, setActiveTab, isMobile, engineOnline = true }: SidebarProps) {
  return (
    <aside
      className={cn(
        'flex flex-col h-full bg-slate-950',
        !isMobile && 'w-64 border-r border-slate-800 sticky top-0'
      )}
    >
      <div className="p-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/defendat-logo.svg"
            alt="Defendat SOC Logo"
            className="w-10 h-10 rounded-lg shadow-lg shadow-blue-900/20"
          />
          <div>
            <h1 className="text-lg font-bold text-white leading-none">Defendat SOC</h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest mt-1 font-semibold">AI IDS / IDP Platform</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 space-y-1 mt-2">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group cursor-pointer',
              activeTab === item.id
                ? 'bg-blue-600/10 text-blue-400 border border-blue-500/10 shadow-[inset_0_0_20px_rgba(59,130,246,0.05)]'
                : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
            )}
          >
            <item.icon
              className={cn(
                'w-4 h-4',
                activeTab === item.id ? 'text-blue-400' : 'text-slate-500 group-hover:text-slate-400'
              )}
            />
            <span className="flex-1 text-left">{item.label}</span>
            {activeTab === item.id && (
              <div className="w-1.5 h-1.5 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.8)]" />
            )}
          </button>
        ))}
      </nav>

      <div className="p-4 mt-auto border-t border-slate-900">
        <div className="bg-slate-900/40 border border-slate-800/50 rounded-xl p-4 relative overflow-hidden">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white truncate">Stephanas Odogu</p>
              <p className="text-[10px] text-slate-500 truncate">SOC Administrator</p>
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-[10px] font-mono text-slate-400 uppercase tracking-tighter">
              <span>BACKEND TELEMETRY</span>
              <span className={engineOnline ? 'text-emerald-400' : 'text-red-400'}>
                {engineOnline ? 'ONLINE' : 'OFFLINE'}
              </span>
            </div>
            <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className={`h-full ${engineOnline ? 'bg-emerald-500 w-full' : 'bg-red-500 w-1/4'}`} />
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
