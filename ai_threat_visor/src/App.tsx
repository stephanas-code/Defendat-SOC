import React from 'react';
import { Sidebar } from './components/dashboard/Sidebar';
import { StatCards } from './components/dashboard/StatCards';
import { LiveAlertFeed } from './components/dashboard/LiveAlertFeed';
import { SeverityAnalytics } from './components/dashboard/SeverityAnalytics';
import { SystemHealth } from './components/dashboard/SystemHealth';
import { ThreatMap } from './components/dashboard/ThreatMap';
import { MLModels } from './components/dashboard/MLModels';
import { PersistenceStatusComponent } from './components/dashboard/PersistenceStatus';
import { ReportPage } from './components/dashboard/ReportPage';
import { SettingsPage } from './components/dashboard/SettingsPage';
import { IdpControlPanel } from './components/dashboard/IdpControlPanel';
import { KubernetesSecurityPanel } from './components/dashboard/KubernetesSecurityPanel';
import { useNetworkData } from './hooks/useNetworkData';
import { Bell, RefreshCcw, ShieldCheck, Search, Info, Menu, Trash2 } from 'lucide-react';
import { Toaster } from './components/ui/sonner';
import { toast } from 'sonner';
import { Sheet, SheetContent, SheetTrigger } from './components/ui/sheet';
import { Button } from './components/ui/button';

function playAlertSiren() {
  if (localStorage.getItem('nids_sound_enabled') === 'false') return;
  try {
    const AudioContext =
      window.AudioContext || (window as unknown as { webkitAudioContext: typeof window.AudioContext }).webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();

    const playTone = (freq: number, start: number, duration: number) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(freq, start);
      osc.frequency.linearRampToValueAtTime(freq * 1.3, start + duration * 0.5);
      osc.frequency.linearRampToValueAtTime(freq, start + duration);

      gain.gain.setValueAtTime(0.12, start);
      gain.gain.exponentialRampToValueAtTime(0.01, start + duration);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(start);
      osc.stop(start + duration);
    };

    playTone(880, ctx.currentTime, 0.4);
    playTone(660, ctx.currentTime + 0.22, 0.4);
  } catch (e) {
    console.error('Failed to play alert sound:', e);
  }
}

function App() {
  const {
    alerts,
    clearAlerts,
    isCapturing,
    setIsCapturing,
    mlModels,
    persistence,
    stats,
    backendStatus,
    idpStatus,
    incidents,
    k8sStatus,
    applications,
    hostStatus,
    wafStatus,
    refreshAll,
    backendHttp,
  } = useNetworkData();

  const [activeTab, setActiveTab] = React.useState('dashboard');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  React.useEffect(() => {
    document.title = 'Defendat SOC — AI IDS/IDP Platform';
    const link = document.querySelector("link[rel~='icon']") as HTMLLinkElement | null;
    if (link) {
      link.type = 'image/svg+xml';
      link.href = '/favicon.svg';
    }
  }, []);

  const lastAlertIdRef = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (alerts.length === 0) return;
    const latestAlert = alerts[0];

    if (lastAlertIdRef.current && lastAlertIdRef.current !== latestAlert.id) {
      if (latestAlert.severity === 'Critical' || latestAlert.severity === 'High') {
        playAlertSiren();
        toast.error(`ALERT: ${latestAlert.severity.toUpperCase()} THREAT DETECTED`, {
          description: `${latestAlert.attackType} from ${latestAlert.sourceIp} to port ${latestAlert.port}`,
          duration: 6000,
          action: {
            label: 'Investigate',
            onClick: () => setActiveTab('alerts'),
          },
        });
      } else {
        toast.warning(`Warning: ${latestAlert.attackType} anomaly detected`, {
          description: `Host ${latestAlert.sourceIp} matched threat signatures.`,
          duration: 4000,
        });
      }
    }

    lastAlertIdRef.current = latestAlert.id;
  }, [alerts]);

  const [isClearing, setIsClearing] = React.useState(false);

  const handleClearAlerts = async () => {
    setIsClearing(true);
    try {
      await clearAlerts();
      toast.success('Database & Telemetry Reset', {
        description: 'All stored alerts, flows, incidents, and deduplication keys cleared.',
      });
    } catch {
      toast.error('Failed to clear alerts');
    } finally {
      setIsClearing(false);
    }
  };

  const handleCaptureToggle = () => {
    setIsCapturing(!isCapturing);
    toast.info(isCapturing ? 'Live stream paused' : 'Live stream resumed');
  };

  const avgModelLatency = React.useMemo(() => {
    const active = mlModels.filter((m) => m.latency && m.latency > 0);
    if (active.length === 0) return 0.0;
    return active.reduce((acc, m) => acc + (m.latency || 0), 0) / active.length;
  }, [mlModels]);

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <div className="space-y-6 lg:space-y-8 animate-in fade-in duration-500">
            <StatCards alerts={alerts} stats={stats} />
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <div className="xl:col-span-2 space-y-6">
                <ThreatMap
                  alerts={alerts}
                  monitoredNodes={stats.infrastructure?.monitoredNodes ?? 0}
                  avgLatencyMs={avgModelLatency}
                />
                <SeverityAnalytics alerts={alerts} />
              </div>
              <div className="space-y-6">
                <LiveAlertFeed alerts={alerts} onClearAlerts={handleClearAlerts} />
                <SystemHealth />
              </div>
            </div>
          </div>
        );
      case 'idp':
        return (
          <IdpControlPanel
            idpStatus={idpStatus}
            incidents={incidents}
            backendHttp={backendHttp}
            onRefresh={refreshAll}
          />
        );
      case 'k8s':
        return (
          <KubernetesSecurityPanel
            k8sStatus={k8sStatus}
            applications={applications}
            hostStatus={hostStatus}
            wafStatus={wafStatus}
            backendHttp={backendHttp}
            onRefresh={refreshAll}
          />
        );
      case 'alerts':
        return (
          <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-2xl font-bold text-white">Live Threat Stream</h2>
                <p className="text-slate-400 text-sm">Detailed log of all detected anomalies and network intrusions</p>
              </div>
              <Button
                onClick={handleClearAlerts}
                disabled={isClearing}
                className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs shadow-lg shadow-red-900/20 self-start sm:self-auto cursor-pointer active:scale-95"
              >
                <Trash2 className={`w-3.5 h-3.5 mr-1.5 ${isClearing ? 'animate-spin' : ''}`} />
                {isClearing ? 'Clearing Stream...' : 'Clear Threat Stream'}
              </Button>
            </div>
            <LiveAlertFeed alerts={alerts} onClearAlerts={handleClearAlerts} expanded />
          </div>
        );
      case 'map':
        return (
          <div className="space-y-6 animate-in zoom-in-95 duration-500">
            <h2 className="text-2xl font-bold text-white">Global Threat Visualization</h2>
            <ThreatMap
              alerts={alerts}
              fullScreen
              monitoredNodes={stats.infrastructure?.monitoredNodes ?? 0}
              avgLatencyMs={avgModelLatency}
            />
          </div>
        );
      case 'models':
        return <MLModels models={mlModels} backendHttp={backendHttp} />;
      case 'data':
        return <PersistenceStatusComponent persistence={persistence} alerts={alerts} />;
      case 'reports':
        return <ReportPage alerts={alerts} stats={stats} />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <div className="text-white">Select a section from the sidebar</div>;
    }
  };

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    setIsMobileMenuOpen(false);
  };

  return (
    <div className="flex min-h-screen bg-[#020617] text-slate-200 selection:bg-blue-500/30 font-sans overflow-hidden">
      <div className="hidden lg:block">
        <Sidebar activeTab={activeTab} setActiveTab={handleTabChange} engineOnline={Boolean(backendStatus?.ok)} />
      </div>

      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        <header className="flex items-center justify-between px-4 lg:px-8 py-4 bg-[#020617]/80 backdrop-blur-md border-b border-slate-900 sticky top-0 z-40">
          <div className="flex items-center gap-4">
            <div className="lg:hidden">
              <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="icon-sm" className="text-slate-400">
                    <Menu className="w-5 h-5" />
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="p-0 border-r-slate-900 bg-slate-950 w-64">
                  <Sidebar activeTab={activeTab} setActiveTab={handleTabChange} isMobile engineOnline={Boolean(backendStatus?.ok)} />
                </SheetContent>
              </Sheet>
            </div>

            <div className="flex items-center gap-3">
              <img src="/defendat-logo.svg" alt="Defendat SOC" className="w-7 h-7" />
              <h2 className="text-lg lg:text-2xl font-bold text-white tracking-tight capitalize truncate">
                {activeTab === 'idp'
                  ? 'IDP & Incident Correlation'
                  : activeTab === 'k8s'
                  ? 'Kubernetes, Host & WAF Security'
                  : activeTab === 'settings'
                  ? 'Settings & Live Server Setup'
                  : activeTab}
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2 lg:gap-4">
            <div className="relative hidden md:block">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search logs..."
                className="bg-slate-900/50 border border-slate-800 rounded-lg py-1.5 pl-10 pr-4 text-sm w-48 lg:w-64 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
              />
            </div>
            <button
              onClick={handleCaptureToggle}
              className={`flex items-center gap-2 px-3 lg:px-4 py-1.5 lg:py-2.5 rounded-lg text-xs lg:text-sm font-semibold transition-all shadow-lg cursor-pointer ${
                isCapturing
                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20 hover:bg-amber-500/20 shadow-amber-900/5'
                  : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 shadow-emerald-900/5'
              }`}
            >
              <RefreshCcw className={`w-3.5 h-3.5 lg:w-4 h-4 ${isCapturing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{isCapturing ? 'Pause Stream' : 'Resume Stream'}</span>
            </button>
            <button
              onClick={handleClearAlerts}
              disabled={isClearing}
              className="flex items-center gap-1.5 px-3 lg:px-4 py-1.5 lg:py-2.5 rounded-lg text-xs lg:text-sm font-bold transition-all shadow-lg bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 hover:text-red-300 shadow-red-900/10 active:scale-95 disabled:opacity-50 cursor-pointer"
              title="Clear all alerts, empty database, and reset live feed"
            >
              <Trash2 className={`w-3.5 h-3.5 lg:w-4 h-4 ${isClearing ? 'animate-spin' : ''}`} />
              <span>{isClearing ? 'Clearing...' : 'Clear Alerts'}</span>
            </button>
            <button className="p-2 lg:p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors relative group">
              <Bell className="w-4 h-4 lg:w-5 h-5" />
              <span className="absolute top-2 lg:top-2.5 right-2 lg:right-2.5 w-1.5 lg:w-2 h-1.5 lg:h-2 bg-blue-500 rounded-full border-2 border-slate-950 animate-pulse" />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-4 lg:p-8 custom-scrollbar">
          <div className="max-w-7xl mx-auto space-y-8 pb-12">
            {renderContent()}

            <footer className="mt-12 pt-8 border-t border-slate-900 flex flex-col md:flex-row items-center justify-between gap-6 text-[10px] lg:text-xs text-slate-500">
              <div className="flex items-center gap-4 lg:gap-8">
                <div>
                  <p className="font-bold text-slate-400 uppercase tracking-widest mb-1">RESEARCHER</p>
                  <p className="font-medium">Stephanas Osanebi Odogu</p>
                </div>
                <div className="h-8 w-px bg-slate-900 hidden sm:block" />
                <div className="hidden sm:block">
                  <p className="font-bold text-slate-400 uppercase tracking-widest mb-1">SUPERVISOR</p>
                  <p className="font-medium">Dr. Oluwasegun I. Adelaiye</p>
                </div>
              </div>
              <div className="text-center md:text-right">
                <div className="flex items-center md:justify-end gap-2 mb-1">
                  <Info className="w-3 h-3 text-blue-500" />
                  <p className="font-semibold text-slate-400">MIVA Open University</p>
                </div>
                <p className="opacity-60 font-mono">© 2026 Defendat SOC. Abuja.</p>
              </div>
            </footer>
          </div>
        </div>
      </main>
      <Toaster theme="dark" position="bottom-right" closeButton richColors />
    </div>
  );
}

export default App;
