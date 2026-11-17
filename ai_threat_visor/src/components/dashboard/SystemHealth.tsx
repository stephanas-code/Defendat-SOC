import { Cpu, Activity, Database, Network, ShieldAlert, CheckCircle } from 'lucide-react';
import { useNetworkData } from '../../hooks/useNetworkData';

export function SystemHealth() {
  const { backendStatus } = useNetworkData();

  const cpuPct = Math.round(backendStatus?.infrastructure?.cpu_load_pct ?? 0);
  const memPct = Math.round(backendStatus?.infrastructure?.memory_used_pct ?? 0);
  const isoInv = backendStatus?.model_metrics?.isoforest?.invocations ?? 0;
  const xgbInv = backendStatus?.model_metrics?.xgboost?.invocations ?? 0;
  const lstmInv = backendStatus?.model_metrics?.lstm_onnx?.invocations ?? 0;
  const activeBlocks = backendStatus?.idp?.active_blocks_count ?? 0;

  const components = [
    {
      component: 'Kafka Event Bus',
      status: backendStatus?.components?.kafka?.ok ? 'online' : 'offline',
      metricLabel: `${backendStatus?.flows?.total ?? 0} flows processed`,
      barPct: backendStatus?.components?.kafka?.ok ? Math.min(100, cpuPct || 5) : 0,
    },
    {
      component: 'Isolation Forest (44-Feature)',
      status: backendStatus?.models?.isoforest ? 'online' : 'offline',
      metricLabel: `${isoInv} runs (${(backendStatus?.model_metrics?.isoforest?.avg_latency_ms ?? 0).toFixed(1)}ms)`,
      barPct: backendStatus?.models?.isoforest ? Math.min(100, Math.round((backendStatus?.model_metrics?.isoforest?.avg_latency_ms ?? 0) * 2)) : 0,
    },
    {
      component: 'XGBoost Classifier',
      status: backendStatus?.models?.xgboost ? 'online' : 'offline',
      metricLabel: `${xgbInv} runs (${(backendStatus?.model_metrics?.xgboost?.avg_latency_ms ?? 0).toFixed(1)}ms)`,
      barPct: backendStatus?.models?.xgboost ? Math.min(100, Math.round((backendStatus?.model_metrics?.xgboost?.avg_latency_ms ?? 0) * 2)) : 0,
    },
    {
      component: 'LSTM Autoencoder (ONNX)',
      status: backendStatus?.models?.lstm_onnx ? 'online' : 'offline',
      metricLabel: `${lstmInv} runs (${(backendStatus?.model_metrics?.lstm_onnx?.avg_latency_ms ?? 0).toFixed(2)}ms)`,
      barPct: backendStatus?.models?.lstm_onnx ? Math.min(100, Math.max(2, Math.round((backendStatus?.model_metrics?.lstm_onnx?.avg_latency_ms ?? 0) * 10))) : 0,
    },
    {
      component: 'TimescaleDB Storage',
      status: backendStatus?.components?.database?.ok ? 'online' : 'offline',
      metricLabel: `${Math.round((backendStatus?.alerts?.table_bytes ?? 0) / 1024)} KB indexed`,
      barPct: backendStatus?.components?.database?.ok ? memPct : 0,
    },
    {
      component: 'IDP Firewall & Redis Sync',
      status: backendStatus?.components?.redis?.ok ? 'online' : 'offline',
      metricLabel: `${activeBlocks} active blocks`,
      barPct: backendStatus?.components?.redis?.ok ? Math.min(100, activeBlocks * 5 + 5) : 0,
    },
  ];

  const attackSensingActive =
    backendStatus?.models?.isoforest || backendStatus?.models?.xgboost || backendStatus?.models?.lstm_onnx;
  const totalAlerts = backendStatus?.alerts?.total || 0;
  const criticalAlerts = backendStatus?.alerts?.critical_total || 0;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-sm font-semibold text-white">Detection Pipeline Status</h3>
        <span className="text-[10px] text-slate-500 flex items-center gap-1">
          <Activity className={`w-3 h-3 ${backendStatus?.ok ? 'text-emerald-500' : 'text-red-500'}`} />
          Status: {backendStatus?.ok ? 'Operational' : 'Degraded'}
        </span>
      </div>

      <div
        className={`mb-6 p-4 rounded-lg border ${
          attackSensingActive ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-red-500/10 border-red-500/20'
        }`}
      >
        <div className="flex items-center gap-3">
          {attackSensingActive ? (
            <ShieldAlert className="w-5 h-5 text-emerald-500" />
          ) : (
            <CheckCircle className="w-5 h-5 text-red-500" />
          )}
          <div className="flex-1">
            <p className={`text-sm font-bold ${attackSensingActive ? 'text-emerald-400' : 'text-red-400'}`}>
              Attack Sensing: {attackSensingActive ? 'ACTIVE' : 'INACTIVE'}
            </p>
            <p className="text-xs text-slate-500">
              {attackSensingActive
                ? `${totalAlerts} total alerts recorded, ${criticalAlerts} critical threats`
                : 'No ML models loaded. System cannot detect attacks.'}
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {components.map((comp, idx) => (
          <div key={idx} className="flex items-center gap-4 group">
            <div className={`p-2 rounded-lg ${comp.status === 'online' ? 'bg-emerald-500/10' : 'bg-orange-500/10'}`}>
              {idx === 0 ? (
                <Network className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} />
              ) : idx < 4 ? (
                <Cpu className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} />
              ) : (
                <Database className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} />
              )}
            </div>

            <div className="flex-1">
              <div className="flex justify-between items-center mb-1">
                <p className="text-xs font-medium text-slate-200">{comp.component}</p>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                    comp.status === 'online' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-orange-500/10 text-orange-400'
                  }`}
                >
                  {comp.status.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      comp.barPct > 80 ? 'bg-red-500' : comp.barPct > 50 ? 'bg-orange-500' : 'bg-blue-500'
                    }`}
                    style={{ width: `${comp.barPct}%` }}
                  />
                </div>
                <span className="text-[10px] font-mono text-slate-400 shrink-0">{comp.metricLabel}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-slate-800">
        <button
          className="w-full py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors bg-slate-800/50 hover:bg-slate-800 rounded-lg cursor-pointer"
          onClick={() => window.open('http://localhost:8000/status', '_blank')}
        >
          View Raw Backend JSON (/status)
        </button>
      </div>
    </div>
  );
}
