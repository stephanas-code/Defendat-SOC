import { NetworkAlert } from '../../types';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import { AlertCircle, ShieldAlert, Wifi, Info, Activity, ArrowRight, ExternalLink, Terminal, Trash2 } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { Button } from '../ui/button';

interface LiveAlertFeedProps {
  alerts: NetworkAlert[];
  onClearAlerts?: () => void;
  expanded?: boolean;
}

export function LiveAlertFeed({ alerts, onClearAlerts, expanded = false }: LiveAlertFeedProps) {
  const filteredAlerts = alerts.filter(a => a.attackType !== 'Normal');

  const getSeverityIcon = (severity: NetworkAlert['severity']) => {
    switch (severity) {
      case 'Critical': return <ShieldAlert className="w-4 h-4 text-red-500" />;
      case 'High': return <AlertCircle className="w-4 h-4 text-orange-500" />;
      case 'Medium': return <Info className="w-4 h-4 text-yellow-500" />;
      default: return <Wifi className="w-4 h-4 text-blue-500" />;
    }
  };

  const getSeverityColor = (severity: NetworkAlert['severity']) => {
    switch (severity) {
      case 'Critical': return 'border-l-red-500 bg-red-500/5 hover:bg-red-500/10';
      case 'High': return 'border-l-orange-500 bg-orange-500/5 hover:bg-orange-500/10';
      case 'Medium': return 'border-l-yellow-500 bg-yellow-500/5 hover:bg-yellow-500/10';
      default: return 'border-l-blue-500 bg-blue-500/5 hover:bg-blue-500/10';
    }
  };

  return (
    <Card className={cn(
      "bg-slate-900 border-slate-800 flex flex-col shadow-2xl overflow-hidden",
      expanded ? "h-full" : "h-[550px]"
    )}>
      <CardHeader className="border-b border-slate-800/50 bg-slate-900/30 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
             <Activity className="w-4 h-4 text-blue-500" />
             <CardTitle className="text-xs font-black text-white uppercase tracking-widest">Threat Stream</CardTitle>
          </div>
          <div className="flex items-center gap-3">
            {onClearAlerts && (
              <button
                onClick={onClearAlerts}
                className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-md transition-all active:scale-95 shadow-sm cursor-pointer"
                title="Clear all alerts and truncate database"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
            <div className="flex items-center gap-2 px-2.5 py-1 bg-black/40 border border-slate-800 rounded-full">
              <span className="flex h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
              <span className="text-[9px] text-slate-400 font-bold font-mono">ACTIVE</span>
            </div>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="flex-1 overflow-y-auto p-3 lg:p-4 space-y-3 custom-scrollbar">
        {filteredAlerts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 space-y-4 opacity-50">
            <Terminal className="w-12 h-12" />
            <p className="text-xs font-bold uppercase tracking-widest font-mono">Awaiting network packets...</p>
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <div 
              key={alert.id}
              className={cn(
                "group border border-slate-800 border-l-4 rounded-xl p-3 lg:p-4 transition-all duration-300",
                getSeverityColor(alert.severity)
              )}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 bg-slate-950 rounded-lg border border-slate-800 group-hover:border-slate-700 transition-colors">
                     {getSeverityIcon(alert.severity)}
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xs font-black text-white uppercase tracking-wider">{alert.attackType}</span>
                    <span className="text-[9px] text-slate-500 font-mono">{alert.id.slice(0, 8).toUpperCase()}</span>
                  </div>
                </div>
                <div className="text-right">
                   <span className="text-[9px] text-slate-400 font-mono block font-bold">
                     {format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                   </span>
                   <span className="text-[9px] font-black text-blue-500 bg-blue-500/10 px-1.5 py-0.5 rounded mt-1 inline-block border border-blue-500/20 uppercase">
                     {alert.location}
                   </span>
                </div>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
                <div className="p-2 bg-slate-950/50 rounded-lg border border-slate-800/50 group-hover:border-slate-800 transition-colors">
                  <p className="text-[8px] text-slate-500 uppercase font-black mb-1 tracking-tighter">Source</p>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-300 truncate">{alert.sourceIp}</span>
                  </div>
                </div>
                <div className="p-2 bg-slate-950/50 rounded-lg border border-slate-800/50 group-hover:border-slate-800 transition-colors">
                  <p className="text-[8px] text-slate-500 uppercase font-black mb-1 tracking-tighter">Target</p>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-slate-300 truncate">{alert.destIp}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between border-t border-slate-800/50 pt-3">
                <div className="flex items-center gap-3">
                  <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono border border-slate-700">
                    {alert.protocol}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    Port <span className="text-slate-300 font-mono font-bold">{alert.port}</span>
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="hidden xs:flex items-center gap-2">
                    <div className="w-12 h-1 bg-slate-800 rounded-full overflow-hidden shadow-inner">
                      <div 
                        className={cn(
                          "h-full transition-all duration-1000",
                          alert.confidence > 0.8 ? "bg-blue-500" : "bg-orange-500"
                        )} 
                        style={{ width: `${alert.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-[9px] font-bold text-slate-500 font-mono">
                      {(alert.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <Button variant="ghost" size="icon-sm" className="h-6 w-6 text-slate-500 hover:text-white">
                    <ExternalLink className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
      
      {!expanded && (
        <div className="px-4 py-2 text-center border-t border-slate-800/50 bg-slate-950/50">
          <p className="text-[9px] text-slate-600 font-mono font-bold uppercase tracking-widest">Analysis v4.2 stable</p>
        </div>
      )}
    </Card>
  );
}