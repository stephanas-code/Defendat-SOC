import { Globe, MapPin, Maximize2, Crosshair } from 'lucide-react';
import { NetworkAlert } from '../../types';
import { cn } from '@/lib/utils';

interface ThreatMapProps {
  alerts: NetworkAlert[];
  fullScreen?: boolean;
}

export function ThreatMap({ alerts, fullScreen = false }: ThreatMapProps) {
  const attackAlerts = alerts.filter(a => a.attackType !== 'Normal').slice(0, 15);
  
  // Aggregate recent hits by country
  const countryHits = alerts.reduce((acc, alert) => {
    if (alert.attackType !== 'Normal') {
      acc[alert.location] = (acc[alert.location] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const topCountries = Object.entries(countryHits)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 4);

  return (
    <div className={cn(
      "bg-slate-950 border border-slate-800 rounded-xl overflow-hidden relative shadow-2xl",
      fullScreen ? "h-[calc(100vh-200px)]" : "h-[500px]"
    )}>
      {/* Background Map Styling */}
      <div className="absolute inset-0 bg-[#020617]">
        {/* Abstract World Grid/Dots using CSS */}
        <div className="absolute inset-0 opacity-20 pointer-events-none"
             style={{ 
               backgroundImage: `radial-gradient(circle at 2px 2px, #3b82f6 1px, transparent 0)`, 
               backgroundSize: '24px 24px' 
             }} 
        />
        
        {/* Glow effect */}
        <div className="absolute inset-0 bg-gradient-to-t from-blue-900/10 via-transparent to-transparent" />
      </div>

      <div className="relative p-6 h-full flex flex-col z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
             <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
                <Globe className="w-5 h-5 text-blue-500 animate-pulse" />
             </div>
             <div>
               <h3 className="text-base font-bold text-white tracking-tight">Global Threat Map</h3>
               <p className="text-[11px] text-slate-400 font-mono">SITUATIONAL_AWARENESS_v2.0</p>
             </div>
          </div>
          
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-4 bg-slate-900/80 border border-slate-800 rounded-lg px-4 py-2 backdrop-blur-md">
               <div className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
                 <span className="text-[10px] text-slate-300 font-bold font-mono">CRITICAL</span>
               </div>
               <div className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]" />
                 <span className="text-[10px] text-slate-300 font-bold font-mono">WARNING</span>
               </div>
               <div className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.8)]" />
                 <span className="text-[10px] text-slate-300 font-bold font-mono">NORMAL</span>
               </div>
            </div>
            <button className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-white">
               <Maximize2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* The Visualization Area */}
        <div className="flex-1 relative border border-slate-800/50 rounded-lg bg-slate-900/20 overflow-hidden group">
           <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-40">
              {/* Fallback stylized world map image */}
              <img 
                src="https://storage.googleapis.com/dala-prod-public-storage/generated-images/b54d72fe-9d32-4c98-9401-ac8ec88e654a/threat-map-overlay-b00764e3-1778760793748.webp"
                alt="World Map" 
                className="w-full h-full object-cover filter brightness-50 contrast-125 saturate-50"
              />
           </div>

           {/* Dynamic Threat Pins */}
           {attackAlerts.map((alert) => {
             const isLan = alert.location === 'Local Network (LAN)' || alert.countryCode === 'LAN';
             const leftPct = isLan
               ? 50
               : Math.max(5, Math.min(95, 50 + (alert.coordinates[1] / 180) * 50));
             const topPct = isLan
               ? 50
               : Math.max(5, Math.min(95, 50 - (alert.coordinates[0] / 90) * 50));

             return (
               <div 
                 key={alert.id}
                 className="absolute transition-all duration-1000 ease-out"
                 style={{ 
                   left: `${leftPct}%`, 
                   top: `${topPct}%` 
                 }}
               >
                 <div className="relative">
                   <div className={cn(
                     "absolute -inset-4 rounded-full animate-ping duration-[3000ms]",
                     alert.severity === 'Critical' ? "bg-red-500/20" : isLan ? "bg-blue-500/20" : "bg-orange-500/20"
                   )} />
                   <div className={cn(
                     "w-3.5 h-3.5 rounded-full border-2 border-slate-950 flex items-center justify-center shadow-lg",
                     alert.severity === 'Critical' ? "bg-red-500" : isLan ? "bg-blue-500" : "bg-orange-500"
                   )}>
                     <div className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />
                   </div>
                   
                   {/* Tooltip on Hover */}
                   <div className="absolute bottom-4 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-950/90 border border-slate-800 p-2.5 rounded-lg text-[9px] font-mono whitespace-nowrap z-50 backdrop-blur-md shadow-2xl">
                     <p className="text-white font-bold">{alert.attackType}</p>
                     <p className="text-slate-300">{alert.sourceIp} → {alert.destIp}:{alert.destPort}</p>
                     <p className="text-blue-400 font-bold">{alert.location}</p>
                   </div>
                 </div>
               </div>
             );
           })}
           
           {/* HUD elements */}
           <div className="absolute top-4 left-4 p-2 bg-slate-950/60 border border-slate-800 rounded font-mono text-[9px] text-blue-400">
              <p>LATENCY: 42ms</p>
              <p>NODES: 1,402</p>
              <p>UPTIME: 99.98%</p>
           </div>
           
           <div className="absolute bottom-4 right-4 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-slate-500 animate-spin-slow" />
              <div className="text-right">
                 <p className="text-[10px] text-slate-300 font-bold uppercase">Scanning Origin</p>
                 <p className="text-[9px] text-slate-500 font-mono">SCAN_MODE: PASSIVE_AI</p>
              </div>
           </div>
        </div>

        {/* Geographic Summary Footer */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
          {topCountries.length > 0 ? topCountries.map(([country, count], i) => (
            <div key={i} className="bg-slate-900/60 border border-slate-800/80 p-3 rounded-xl backdrop-blur-sm group hover:border-slate-600 transition-colors">
              <div className="flex items-center gap-2 mb-2">
                <div className="p-1.5 bg-slate-800 rounded-md">
                   <MapPin className="w-3 h-3 text-blue-400" />
                </div>
                <span className="text-[11px] font-bold text-slate-200 uppercase truncate">{country}</span>
              </div>
              <div className="flex items-end justify-between font-mono">
                <span className="text-lg font-black text-white">{count}</span>
                <span className="text-[10px] text-red-400 mb-1 font-bold">+{(Math.random() * 10).toFixed(0)}%</span>
              </div>
            </div>
          )) : (
            [1,2,3,4].map(i => (
              <div key={i} className="bg-slate-900/40 border border-slate-800/50 p-3 rounded-xl animate-pulse h-16" />
            ))
          )}
        </div>
      </div>
    </div>
  );
}