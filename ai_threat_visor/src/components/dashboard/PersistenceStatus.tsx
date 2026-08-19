import { Database, HardDrive, ShieldCheck, History, ArrowUpRight, Activity } from 'lucide-react';
import { PersistenceStatus } from '../../types';

interface PersistenceProps {
  persistence: PersistenceStatus;
  alerts: NetworkAlert[];
}

export function PersistenceStatusComponent({ persistence, alerts }: PersistenceProps) {
  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-xs text-slate-500 uppercase font-black tracking-widest mb-4">Active Storage</p>
          <div className="flex items-center gap-4">
            <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
              <Database className="w-6 h-6 text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-black text-white">{persistence.database}</p>
              <div className="flex items-center gap-1.5 mt-1">
                 <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                 <span className="text-[10px] text-emerald-400 font-bold uppercase font-mono">CONNECTED</span>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-xs text-slate-500 uppercase font-black tracking-widest mb-4">Log Persistence</p>
          <div className="flex items-center gap-4">
            <div className="p-3 bg-purple-500/10 rounded-xl border border-purple-500/20">
              <HardDrive className="w-6 h-6 text-purple-500" />
            </div>
            <div>
              <p className="text-2xl font-black text-white">{(persistence.totalLogs ?? 0).toLocaleString()}</p>
              <p className="text-[10px] text-slate-500 font-bold uppercase mt-1">INDEXED RECORDS</p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-xs text-slate-500 uppercase font-black tracking-widest mb-4">Storage Density</p>
          <div className="flex items-center gap-4">
            <div className="p-3 bg-orange-500/10 rounded-xl border border-orange-500/20">
              <Activity className="w-6 h-6 text-orange-500" />
            </div>
            <div>
              <p className="text-2xl font-black text-white">{persistence.storageUsed ?? '0 B'}</p>
              <p className="text-[10px] text-slate-500 font-bold uppercase mt-1">OPTIMIZED COLD-STORAGE</p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-xs text-slate-500 uppercase font-black tracking-widest mb-4">Integrity Scan</p>
          <div className="flex items-center gap-4">
            <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/20">
              <ShieldCheck className="w-6 h-6 text-emerald-500" />
            </div>
            <div>
              <p className="text-2xl font-black text-white">HEALTHY</p>
              <p className="text-[10px] text-slate-500 font-bold uppercase mt-1">CHECKSUM VERIFIED</p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-white uppercase tracking-tight">System Persistence Logs</h3>
          <button className="text-xs text-blue-500 hover:text-blue-400 font-bold">DOWNLOAD_MANIFEST</button>
        </div>
        <div className="p-6 space-y-4">
          {alerts.length > 0 ? (
            alerts.slice(0, 10).map((alert) => (
              <div key={alert.id} className="flex items-center justify-between p-4 bg-black/20 border border-slate-800/50 rounded-lg group hover:border-slate-700 transition-colors">
                <div className="flex items-center gap-4">
                  <div className="p-2 bg-slate-800 rounded">
                     <History className="w-4 h-4 text-slate-500" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-white">DB Write Entry #{alert.id.substring(0, 8)}</p>
                    <p className="text-[10px] text-slate-500">
                      PROCESSED: {new Date(alert.timestamp).toLocaleString()} | SOURCE: {alert.sourceIp} | TARGET_PORT: {alert.port}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 font-mono">
                   <span className="text-[10px] text-emerald-400 font-bold">PERSISTED_SUCCESS</span>
                   <ArrowUpRight className="w-4 h-4 text-slate-700 group-hover:text-blue-500 transition-colors" />
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-slate-500 text-sm font-medium">
              No database write logs recorded yet. Active capture database writes will appear here in real-time.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}