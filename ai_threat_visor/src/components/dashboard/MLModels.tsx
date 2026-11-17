import React, { useEffect, useState } from 'react';
import { Cpu, BrainCircuit, BarChart3, Clock, CheckCircle2, AlertCircle, XCircle } from 'lucide-react';
import { MLModelStats } from '../../types';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

interface MLModelsProps {
  models: MLModelStats[];
  backendHttp?: string;
}

type BackendModelDetail = {
  loaded: boolean;
  purpose: string;
  file: string;
  file_size_bytes?: number;
  n_estimators?: number | null;
  threshold?: number;
  confidence_threshold?: number;
  recon_error_threshold?: number;
  classes?: string[];
};

const formatSize = (bytes?: number) => {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
};

export function MLModels({ models, backendHttp = 'http://localhost:8000' }: MLModelsProps) {
  const [details, setDetails] = useState<Record<string, BackendModelDetail>>({});

  useEffect(() => {
    let active = true;
    fetch(`${backendHttp.replace(/\/+$/, '')}/models`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (active && data?.models) {
          setDetails(data.models);
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [backendHttp]);

  const performanceHistory = models.map((m) => ({
    time: m.name.substring(0, 12),
    latency: m.latency != null ? Number(m.latency) : 0,
    invocations: m.invocations ?? 0,
  }));

  const hasActiveModels = models.some((m) => m.status === 'loaded');

  const keyForIndex = (idx: number) => (idx === 0 ? 'xgboost' : idx === 1 ? 'isoforest' : 'lstm_onnx');

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
        {models.map((model, idx) => {
          const k = keyForIndex(idx);
          const d = details[k];
          return (
            <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden group">
              <div className="flex items-start justify-between mb-6">
                <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
                  {idx === 2 ? <BrainCircuit className="w-6 h-6 text-purple-400" /> : <Cpu className="w-6 h-6 text-blue-400" />}
                </div>
                <div className="flex items-center gap-2">
                  <span className={`flex h-2 w-2 rounded-full ${model.status === 'loaded' ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
                  <span className={`text-[10px] font-bold uppercase tracking-widest font-mono ${model.status === 'loaded' ? 'text-emerald-400' : 'text-red-400'}`}>
                    {model.status}
                  </span>
                </div>
              </div>

              <h3 className="text-lg font-bold text-white mb-1">{model.name}</h3>
              <p className="text-xs text-slate-400 mb-6 font-mono truncate">{d?.file || 'artifacts/'}</p>

              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="p-3 bg-black/30 rounded-lg border border-slate-800/50">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Flows Scored</p>
                  <p className="text-xl font-black text-white font-mono">{(model.invocations ?? 0).toLocaleString()}</p>
                </div>
                <div className="p-3 bg-black/30 rounded-lg border border-slate-800/50">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Artifact Size</p>
                  <p className="text-xl font-black text-white font-mono">{formatSize(d?.file_size_bytes)}</p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5" /> Live Avg Inference Latency
                  </span>
                  <span className="text-white font-mono font-bold">
                    {model.latency != null && model.latency > 0 ? `${model.latency.toFixed(2)} ms` : '0.00 ms'}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500"
                    style={{ width: `${Math.min(100, (model.latency ?? 0) * 2)}%` }}
                  />
                </div>
                <p className="text-[10px] text-slate-500 font-mono">
                  Last run: {model.lastRun ? new Date(model.lastRun).toLocaleTimeString() : 'No flows evaluated yet'}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <BarChart3 className="w-5 h-5 text-blue-500" />
              <h3 className="font-bold text-white uppercase tracking-tight">Measured Inference Latency (ms)</h3>
            </div>
          </div>

          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={performanceHistory}>
                <defs>
                  <linearGradient id="colorAcc" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="latency" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorAcc)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h3 className="font-bold text-white uppercase tracking-tight mb-6">Loaded XGBoost Attack Classes & Thresholds</h3>
          <div className="space-y-4">
            <div className={`flex items-start gap-4 p-4 bg-black/20 border ${hasActiveModels ? 'border-slate-800' : 'border-red-500/30'} rounded-lg`}>
              <div className={`p-2 ${hasActiveModels ? 'bg-emerald-500/10' : 'bg-red-500/10'} rounded-full`}>
                {hasActiveModels ? <CheckCircle2 className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-red-500" />}
              </div>
              <div>
                <p className="text-sm font-bold text-white">Active Thresholds</p>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  IsolationForest: {details.isoforest?.threshold ?? 0.65} | XGBoost Confidence: {details.xgboost?.confidence_threshold ?? 0.70} | LSTM Recon Error: {details.lstm_onnx?.recon_error_threshold ?? 0.05}
                </p>
              </div>
            </div>

            <div className="p-4 bg-black/20 border border-slate-800 rounded-lg">
              <p className="text-xs font-bold uppercase text-slate-400 mb-3">
                Trained Classification Labels ({details.xgboost?.classes?.length ?? 0} Classes in xgboost_labels.json)
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(details.xgboost?.classes || []).map((cls) => (
                  <span key={cls} className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-blue-400">
                    {cls}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
