import { Cpu, BrainCircuit, BarChart3, Clock, CheckCircle2, AlertCircle, XCircle } from 'lucide-react';
import { MLModelStats } from '../../types';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

interface MLModelsProps {
  models: MLModelStats[];
}

export function MLModels({ models }: MLModelsProps) {
  // Build a lightweight latency history from provided model stats (last N points)
  const performanceHistory = (() => {
    const points = [] as Array<{ time: string; latency: number }>;
    // Use each model entry as a sample point (fallback to 0)
    for (let i = 0; i < models.length; i++) {
      const m = models[i];
      points.push({ time: m.name.substring(0, 10), latency: m.latency != null ? Number(m.latency) : 0 });
    }
    return points.length ? points : [{ time: 'n/a', latency: 0 }];
  })();

  // Check if any models are actually loaded
  const hasActiveModels = models.some(m => m.status === 'loaded');

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {!hasActiveModels && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-6">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-500" />
            <div>
              <p className="text-sm font-bold text-red-400">No ML Models Loaded</p>
              <p className="text-xs text-red-300/70">Train models using scripts in the /scripts directory before deployment.</p>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {models.map((model, idx) => (
          <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden group">
            <div className="flex items-start justify-between mb-6">
              <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
                {idx === 2 ? <BrainCircuit className="w-6 h-6 text-purple-400" /> : <Cpu className="w-6 h-6 text-blue-400" />}
              </div>
              <div className="flex items-center gap-2">
                 <span className={`flex h-2 w-2 rounded-full ${model.status === 'loaded' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
                 <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${model.status === 'loaded' ? 'text-emerald-400' : 'text-red-400'}`}>{model.status}</span>
              </div>
            </div>
            
            <h3 className="text-lg font-bold text-white mb-1">{model.name}</h3>
            <p className="text-xs text-slate-500 mb-6 font-medium">Layered Ensemble Phase {idx + 1}</p>
            
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="p-3 bg-black/30 rounded-lg border border-slate-800/50">
                 <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Accuracy</p>
                 <p className="text-xl font-black text-white">{model.accuracy != null ? `${(model.accuracy * 100).toFixed(1)}%` : 'N/A'}</p>
              </div>
              <div className="p-3 bg-black/30 rounded-lg border border-slate-800/50">
                 <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">F1-Score</p>
                 <p className="text-xl font-black text-white">{model.f1Score != null ? `${(model.f1Score * 100).toFixed(1)}%` : 'N/A'}</p>
              </div>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5" /> Inference Latency
                </span>
                <span className="text-white font-mono font-bold">{model.latency != null ? `${model.latency.toFixed(1)}ms` : 'N/A'}</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500"
                  style={{ width: `${((model.latency ?? 0) / 100) * 100}%` }}
                />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <BarChart3 className="w-5 h-5 text-blue-500" />
              <h3 className="font-bold text-white uppercase tracking-tight">Latency Trend (ms)</h3>
            </div>
            <select className="bg-slate-950 border border-slate-800 rounded px-3 py-1 text-[10px] text-slate-400 outline-none">
               <option>Last 24 Hours</option>
               <option>Last 7 Days</option>
            </select>
          </div>
          
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={performanceHistory}>
                <defs>
                  <linearGradient id="colorAcc" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis 
                  dataKey="time" 
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
                  contentStyle={{ 
                    backgroundColor: '#0f172a', 
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="latency" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  fillOpacity={1} 
                  fill="url(#colorAcc)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h3 className="font-bold text-white uppercase tracking-tight mb-8">Model Pipeline Status</h3>
          <div className="space-y-6">
            <div className={`flex items-start gap-4 p-4 bg-black/20 border ${hasActiveModels ? 'border-slate-800' : 'border-red-500/30'} rounded-lg`}>
               <div className={`p-2 ${hasActiveModels ? 'bg-emerald-500/10' : 'bg-red-500/10'} rounded-full`}>
                  {hasActiveModels ? <CheckCircle2 className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
               </div>
               <div>
                 <p className="text-sm font-bold text-white">Detection Pipeline</p>
                 <p className="text-xs text-slate-500 mt-1">
                   {hasActiveModels 
                     ? `${models.filter(m => m.status === 'loaded').length}/${models.length} models active and processing alerts.` 
                     : 'No models loaded. System cannot detect anomalies without trained models.'}
                 </p>
               </div>
            </div>
            <div className={`flex items-start gap-4 p-4 bg-black/20 border ${hasActiveModels ? 'border-slate-800' : 'border-red-500/30'} rounded-lg`}>
               <div className={`p-2 ${hasActiveModels ? 'bg-emerald-500/10' : 'bg-red-500/10'} rounded-full`}>
                  {hasActiveModels ? <CheckCircle2 className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
               </div>
               <div>
                 <p className="text-sm font-bold text-white">Inference Engine</p>
                 <p className="text-xs text-slate-500 mt-1">
                   {hasActiveModels 
                     ? 'Real-time anomaly detection operational with ensemble voting.' 
                     : 'Inference engine inactive. Train models using scripts/train_*.py'}
                 </p>
               </div>
            </div>
            <div className={`flex items-start gap-4 p-4 bg-black/20 border ${hasActiveModels ? 'border-slate-800' : 'border-blue-500/20'} rounded-lg`}>
               <div className={`p-2 ${hasActiveModels ? 'bg-emerald-500/10' : 'bg-blue-500/10'} rounded-full`}>
                  {hasActiveModels ? <CheckCircle2 className="w-5 h-5 text-emerald-500" /> : <AlertCircle className="w-5 h-5 text-blue-500" />}
               </div>
               <div>
                 <p className="text-sm font-bold text-white">Data Pipeline</p>
                 <p className="text-xs text-slate-500 mt-1">
                   {hasActiveModels 
                     ? 'Kafka consumer, inference scoring, and database persistence are fully operational and processing traffic.' 
                     : 'Kafka consumer and database persistence operational. Ready for model training.'}
                 </p>
               </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}