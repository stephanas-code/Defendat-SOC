import { Cpu, Activity, Database, Network, ShieldAlert, CheckCircle } from 'lucide-react';
import { SystemHealth as SystemHealthType } from '../../types';
import { useNetworkData } from '../../hooks/useNetworkData';

export function SystemHealth() {
  const { backendStatus } = useNetworkData();

  const components: SystemHealthType[] = [
    {
      component: 'Traffic Sensor',
      status: backendStatus?.components?.kafka?.ok ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.components?.kafka?.ok ? 15 : 0
    },
    {
      component: 'Isolation Forest',
      status: backendStatus?.models?.isoforest ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.models?.isoforest ? 25 : 0
    },
    {
      component: 'XGBoost Classifier',
      status: backendStatus?.models?.xgboost ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.models?.xgboost ? 40 : 0
    },
    {
      component: 'LSTM Autoencoder',
      status: backendStatus?.models?.lstm_onnx ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.models?.lstm_onnx ? 35 : 0
    },
    {
      component: 'TimescaleDB',
      status: backendStatus?.components?.database?.ok ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.components?.database?.ok ? 10 : 0
    },
    {
      component: 'Redis Cache',
      status: backendStatus?.components?.redis?.ok ? 'online' : 'offline',
      uptime: 'active',
      load: backendStatus?.components?.redis?.ok ? 5 : 0
    }
  ];

  const attackSensingActive = backendStatus?.models?.isoforest || backendStatus?.models?.xgboost || backendStatus?.models?.lstm_onnx;
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

      {/* Attack Sensing Status */}
      <div className={`mb-6 p-4 rounded-lg border ${attackSensingActive ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
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
                ? `${totalAlerts} total alerts detected, ${criticalAlerts} critical threats`
                : 'No ML models loaded. System cannot detect attacks.'}
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {components.map((comp, idx) => (
          <div key={idx} className="flex items-center gap-4 group">
            <div className={`p-2 rounded-lg ${
              comp.status === 'online' ? 'bg-emerald-500/10' : 'bg-orange-500/10'
            }`}>
              {idx === 0 ? <Network className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} /> : 
               idx < 4 ? <Cpu className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} /> : 
               <Database className={`w-4 h-4 ${comp.status === 'online' ? 'text-emerald-400' : 'text-orange-400'}`} />}
            </div>
            
            <div className="flex-1">
              <div className="flex justify-between items-center mb-1">
                <p className="text-xs font-medium text-slate-200">{comp.component}</p>
                <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                  comp.status === 'online' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-orange-500/10 text-orange-400'
                }`}>
                  {comp.status.toUpperCase()}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-1000 ${
                      comp.load > 80 ? 'bg-red-500' : comp.load > 50 ? 'bg-orange-500' : 'bg-blue-500'
                    }`}
                    style={{ width: `${comp.load}%` }}
                  />
                </div>
                <span className="text-[10px] text-slate-500 w-6">{comp.load}%</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-slate-800 space-y-3">
        <button 
          className="w-full py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors bg-slate-800/50 hover:bg-slate-800 rounded-lg"
          onClick={() => window.open('http://localhost:8000/status', '_blank')}
        >
          View API Status
        </button>
        {!attackSensingActive && (
          <button 
            className="w-full py-2 text-xs font-medium text-blue-400 hover:text-white transition-colors bg-blue-500/10 hover:bg-blue-500/20 rounded-lg border border-blue-500/20"
            onClick={() => window.open('https://github.com/your-repo/blob/main/scripts/', '_blank')}
          >
            Train ML Models
          </button>
        )}
      </div>
    </div>
  );
}