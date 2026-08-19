import { Shield, Server, Database, Globe, AlertTriangle, Settings, FileText, LayoutDashboard, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '../ui/button';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isMobile?: boolean;
}

const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard', id: 'dashboard' },
  { icon: AlertTriangle, label: 'Live Alerts', id: 'alerts' },
  { icon: Globe, label: 'Threat Map', id: 'map' },
  { icon: Server, label: 'ML Models', id: 'models' },
  { icon: Database, label: 'Persistence', id: 'data' },
  { icon: FileText, label: 'Reports', id: 'reports' },
  { icon: Settings, label: 'Settings', id: 'settings' },
];

export function Sidebar({ activeTab, setActiveTab, isMobile }: SidebarProps) {
  return (
    <aside className={cn(
      "flex flex-col h-full bg-slate-950",
      !isMobile && "w-64 border-r border-slate-800 sticky top-0"
    )}>
      <div className="p-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600 rounded-lg shadow-lg shadow-blue-900/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white leading-none">AI-NIDS</h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest mt-1 font-semibold">Intrusion Defense</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 px-3 space-y-1 mt-4">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={cn(
              "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group",
              activeTab === item.id 
                ? "bg-blue-600/10 text-blue-400 border border-blue-500/10 shadow-[inset_0_0_20px_rgba(59,130,246,0.05)]" 
                : "text-slate-400 hover:bg-slate-900/50 hover:text-slate-200"
            )}
          >
            <item.icon className={cn(
              "w-4 h-4",
              activeTab === item.id ? "text-blue-400" : "text-slate-500 group-hover:text-slate-400"
            )} />
            <span className="flex-1 text-left">{item.label}</span>
            {activeTab === item.id && (
              <div className="w-1.5 h-1.5 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.8)]" />
            )}
          </button>
        ))}
      </nav>

      <div className="p-4 mt-auto border-t border-slate-900">
        <div className="bg-slate-900/40 border border-slate-800/50 rounded-xl p-4 relative overflow-hidden group hover:border-slate-700 transition-colors transition-all duration-300">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center overflow-hidden">
               <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=Stephanas&backgroundColor=b6e3f4" alt="Profile" className="w-full h-full object-cover" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white truncate">Stephanas Odogu</p>
              <p className="text-[10px] text-slate-500 truncate">Security Researcher</p>
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-[10px] font-mono text-slate-400 uppercase tracking-tighter">
              <span>ENGINE STATUS</span>
              <span className="text-emerald-400">ONLINE</span>
            </div>
            <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-emerald-500 w-[100%] animate-pulse" />
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}