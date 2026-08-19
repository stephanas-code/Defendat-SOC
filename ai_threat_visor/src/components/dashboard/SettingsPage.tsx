import React from 'react';
import { Settings as SettingsIcon, Shield, Bell, User, Monitor, Key, HelpCircle, Save, Sliders, Lock, Zap, Copy, Check, Volume2, VolumeX, Eye, EyeOff } from 'lucide-react';
import { toast } from 'sonner';
import { Switch } from '../ui/switch';
import { Label } from '../ui/label';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { cn } from '@/lib/utils';

export function SettingsPage() {
  const [activeSection, setActiveSection] = React.useState('Security Policies');
  const [isSaving, setIsSaving] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const [showKey, setShowKey] = React.useState(false);

  // Security Policies Settings
  const [sensitivity, setSensitivity] = React.useState(85);
  const [modules, setModules] = React.useState([
    { id: 'dpi', label: 'Deep Packet Inspection (DPI)', enabled: true },
    { id: 'flow', label: 'Flow-based Anomaly Engine', enabled: true },
    { id: 'bayes', label: 'Bayesian Behavioral Analysis', enabled: false },
    { id: 'geoip', label: 'Geo-IP Threat Intel Sync', enabled: true },
  ]);

  // Profile Settings
  const [profile, setProfile] = React.useState({
    name: 'Stephanas Odogu',
    email: 'stephanas.odogu@example.com',
    role: 'Security Researcher',
    institution: 'MIVA Open University',
  });

  // Alert Notifications Settings
  const [notifications, setNotifications] = React.useState({
    emailAlerts: false,
    pushNotifications: true,
    soundEnabled: localStorage.getItem('nids_sound_enabled') !== 'false', // Default true
    slackWebhook: '',
  });

  // Display Settings
  const [display, setDisplay] = React.useState({
    compactMode: false,
    mapStyle: 'cyber',
    refreshRate: '5',
  });

  // API Keys
  const apiKey = 'nids_live_ak_7a8b9c1d2e3f4g5h6i7j8k9l0m1n2o3p';

  const toggleModule = (id: string) => {
    setModules(prev => prev.map(mod => 
      mod.id === id ? { ...mod, enabled: !mod.enabled } : mod
    ));
  };

  const handleSave = () => {
    setIsSaving(true);
    // Persist sound setting to localStorage so the notification engine can read it
    localStorage.setItem('nids_sound_enabled', notifications.soundEnabled.toString());
    
    setTimeout(() => {
      setIsSaving(false);
      toast.success('Configuration Saved', {
        description: 'System parameters have been updated successfully.'
      });
    }, 800);
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(apiKey);
    setCopied(true);
    toast.success('API Key Copied', {
      description: 'API key copied to your clipboard.'
    });
    setTimeout(() => setCopied(false), 2000);
  };

  const sections = [
    { icon: Shield, label: 'Security Policies' },
    { icon: User, label: 'Profile Settings' },
    { icon: Bell, label: 'Alert Notifications' },
    { icon: Monitor, label: 'Display Interface' },
    { icon: Key, label: 'API Keys' },
    { icon: HelpCircle, label: 'Documentation' },
  ];

  const renderSectionContent = () => {
    switch (activeSection) {
      case 'Security Policies':
        return (
          <div className="space-y-8">
            {/* Sensitivity Slider */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                  <Zap className="w-3 h-3 text-yellow-500" />
                  Detection Sensitivity
                </Label>
                <span className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded">
                  {sensitivity / 100} ({sensitivity > 80 ? 'AGGRESSIVE' : sensitivity > 40 ? 'BALANCED' : 'PASSIVE'})
                </span>
              </div>
              <input 
                type="range" 
                className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-blue-500 hover:accent-blue-400 transition-all"
                min="0" max="100" 
                value={sensitivity}
                onChange={(e) => setSensitivity(parseInt(e.target.value))}
              />
              <div className="flex justify-between text-[10px] text-slate-600 font-mono font-bold uppercase tracking-tighter">
                <span>0.0 Passive</span>
                <span>0.5 Standard</span>
                <span>1.0 Paranoid</span>
              </div>
            </div>

            {/* Modules Toggles */}
            <div className="space-y-6">
               <Label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center gap-2 mb-4">
                 <Shield className="w-3 h-3 text-emerald-500" />
                 Active Detection Modules
               </Label>
               <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                 {modules.map((mod) => (
                   <div 
                     key={mod.id} 
                     className={cn(
                       "flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl hover:border-slate-700 transition-colors group",
                       mod.enabled ? "ring-1 ring-blue-500/20" : "opacity-60"
                     )}
                   >
                     <div className="flex flex-col gap-0.5">
                       <span className="text-sm font-bold text-slate-200">{mod.label}</span>
                       <span className="text-[10px] text-slate-500 font-mono">MODULE_ID: {mod.id.toUpperCase()}</span>
                     </div>
                     <Switch 
                       checked={mod.enabled} 
                       onCheckedChange={() => toggleModule(mod.id)}
                     />
                   </div>
                 ))}
               </div>
            </div>

            {/* Advanced Settings */}
            <div className="p-4 bg-blue-500/5 border border-blue-500/10 rounded-xl flex items-start gap-4">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Lock className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-200">Kernel-level Hardening</p>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                  Enable high-performance traffic interception via eBPF. This reduces latency but requires root-level cluster permissions.
                </p>
                <button className="mt-3 text-[10px] font-black text-blue-400 hover:text-blue-300 uppercase tracking-widest">Configure Permissions →</button>
              </div>
            </div>
          </div>
        );

      case 'Profile Settings':
        return (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">Researcher Full Name</Label>
                <input 
                  type="text" 
                  value={profile.name} 
                  onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">Email Address</Label>
                <input 
                  type="email" 
                  value={profile.email} 
                  onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">System Role</Label>
                <input 
                  type="text" 
                  value={profile.role} 
                  onChange={(e) => setProfile({ ...profile, role: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">Affiliation / Institution</Label>
                <input 
                  type="text" 
                  value={profile.institution} 
                  onChange={(e) => setProfile({ ...profile, institution: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all"
                />
              </div>
            </div>
            
            <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl flex items-center gap-4">
              <div className="w-12 h-12 rounded-full overflow-hidden border border-slate-700 bg-slate-800 flex items-center justify-center">
                 <img src="https://api.dicebear.com/7.x/avataaars/svg?seed=Stephanas&backgroundColor=b6e3f4" alt="Avatar" className="w-full h-full object-cover" />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-200">Researcher Identity Avatar</p>
                <p className="text-xs text-slate-500">Avatar generated automatically via DiceBear avatars.</p>
              </div>
            </div>
          </div>
        );

      case 'Alert Notifications':
        return (
          <div className="space-y-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-yellow-500/10 rounded-lg">
                    {notifications.soundEnabled ? <Volume2 className="w-5 h-5 text-yellow-500" /> : <VolumeX className="w-5 h-5 text-slate-500" />}
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">Audible Intrusion Warning Sound</p>
                    <p className="text-xs text-slate-500">Play a custom alert siren sound when critical/high attacks are detected.</p>
                  </div>
                </div>
                <Switch 
                  checked={notifications.soundEnabled} 
                  onCheckedChange={(val) => setNotifications({ ...notifications, soundEnabled: val })}
                />
              </div>

              <div className="flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-blue-500/10 rounded-lg">
                    <Bell className="w-5 h-5 text-blue-500" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">Browser Desktop Push Notifications</p>
                    <p className="text-xs text-slate-500">Show native toast notices on your desktop for incoming anomalies.</p>
                  </div>
                </div>
                <Switch 
                  checked={notifications.pushNotifications} 
                  onCheckedChange={(val) => setNotifications({ ...notifications, pushNotifications: val })}
                />
              </div>

              <div className="flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/10 rounded-lg">
                    <Shield className="w-5 h-5 text-purple-500" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">Email Digest Alert Summaries</p>
                    <p className="text-xs text-slate-500">Send an hourly summary of security events to {profile.email}.</p>
                  </div>
                </div>
                <Switch 
                  checked={notifications.emailAlerts} 
                  onCheckedChange={(val) => setNotifications({ ...notifications, emailAlerts: val })}
                />
              </div>
            </div>

            <div className="space-y-2 border-t border-slate-800/80 pt-6">
              <Label className="text-xs font-bold text-slate-400">Slack Webhook URL (SIEM Integration)</Label>
              <input 
                type="text" 
                value={notifications.slackWebhook} 
                onChange={(e) => setNotifications({ ...notifications, slackWebhook: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all font-mono"
              />
            </div>
          </div>
        );

      case 'Display Interface':
        return (
          <div className="space-y-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl">
                <div>
                  <p className="text-sm font-bold text-slate-200">Stream Compact Density Mode</p>
                  <p className="text-xs text-slate-500">Reduce padding and spacing in the live alert feeds to fit more lines.</p>
                </div>
                <Switch 
                  checked={display.compactMode} 
                  onCheckedChange={(val) => setDisplay({ ...display, compactMode: val })}
                />
              </div>

              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">Threat Map Projection Style</Label>
                <select 
                  value={display.mapStyle} 
                  onChange={(e) => setDisplay({ ...display, mapStyle: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 outline-none transition-all"
                >
                  <option value="cyber">Cyber Hologram (Dark Blue)</option>
                  <option value="classic">Classic Vector (Gray/Slate)</option>
                  <option value="satellite">Detailed Satellite (Topographic)</option>
                </select>
              </div>

              <div className="space-y-2">
                <Label className="text-xs font-bold text-slate-400">Real-Time Refresh Rate (Seconds)</Label>
                <select 
                  value={display.refreshRate} 
                  onChange={(e) => setDisplay({ ...display, refreshRate: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 focus:border-blue-500 outline-none transition-all"
                >
                  <option value="1">Instantaneous (1s)</option>
                  <option value="5">Realtime Standard (5s)</option>
                  <option value="10">Throttled (10s)</option>
                  <option value="30">Heavy Traffic (30s)</option>
                </select>
              </div>
            </div>
          </div>
        );

      case 'API Keys':
        return (
          <div className="space-y-6">
            <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-white">Live Monitoring API Credential</p>
                  <p className="text-[10px] text-slate-500 font-mono">SCOPE: ALERTS_READ, ALERTS_WRITE</p>
                </div>
                <div className="flex items-center gap-2">
                  <Button 
                    variant="ghost" 
                    size="icon-sm"
                    className="text-slate-400 hover:text-white"
                    onClick={() => setShowKey(!showKey)}
                  >
                    {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                  <Button 
                    variant="ghost" 
                    size="icon-sm"
                    className="text-slate-400 hover:text-white"
                    onClick={copyApiKey}
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </Button>
                </div>
              </div>
              
              <div className="bg-slate-950 border border-slate-900 rounded-lg p-3 font-mono text-xs text-slate-300 break-all select-all flex items-center justify-between">
                <span>{showKey ? apiKey : '••••••••••••••••••••••••••••••••••••••••••••••••'}</span>
              </div>
            </div>

            <div className="p-4 bg-slate-950/20 border border-slate-800/80 rounded-xl space-y-2">
              <p className="text-xs font-bold text-slate-400">SIEM / External Ingestion</p>
              <p className="text-xs text-slate-500 leading-relaxed">
                Use this API key in your custom python collectors or network agents to ingest raw flow logs into the `/ingest/alert` endpoint directly.
              </p>
            </div>
          </div>
        );

      case 'Documentation':
        return (
          <div className="space-y-6 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
            <div className="space-y-2">
              <h4 className="text-sm font-bold text-white">System Architecture Overview</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                This project represents a layered, hybrid Network Intrusion Detection (NIDS) and Prevention (NIP) framework utilizing both unsupervised anomaly profiling and supervised multi-class classification.
              </p>
            </div>

            <div className="space-y-2 border-t border-slate-800/60 pt-4">
              <h4 className="text-sm font-bold text-white">1. Anomaly Profiling (Isolation Forest)</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Trained exclusively on benign flow benchmarks derived from the CIC-IDS2017 dataset. It scores flow feature vectors dynamically. Scores above `ISOFOREST_THRESHOLD` trigger the anomaly flag.
              </p>
            </div>

            <div className="space-y-2 border-t border-slate-800/60 pt-4">
              <h4 className="text-sm font-bold text-white">2. Attack Classification (XGBoost)</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Trained on mixed attack vector traffic. Evaluates flows across multi-class scenarios to categorize exact attack types (DDoS LOIT, Port Scan, Botnet, Web Injection, etc.) with a confidence factor.
              </p>
            </div>

            <div className="space-y-2 border-t border-slate-800/60 pt-4">
              <h4 className="text-sm font-bold text-white">3. Temporal Analysis (LSTM Autoencoder)</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Uses a sequence builder of size 10 to evaluate sliding windows of normal IP behavior. Re-construction errors above `LSTM_RECON_ERROR_THRESHOLD` detect zero-day or timing-based anomalies.
              </p>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.1)]">
            <SettingsIcon className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white tracking-tight">System Configuration</h2>
            <p className="text-slate-400 text-sm font-medium">Manage security policies and engine parameters</p>
          </div>
        </div>
        <Button 
          onClick={handleSave} 
          disabled={isSaving}
          className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-900/20 font-bold"
        >
          {isSaving ? <span className="flex items-center gap-2"><Zap className="w-4 h-4 animate-spin" /> Saving...</span> : <><Save className="w-4 h-4 mr-2" /> Save All Changes</>}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        <div className="md:col-span-3 space-y-1">
          {sections.map((item, i) => (
            <button 
              key={i} 
              onClick={() => setActiveSection(item.label)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all",
                activeSection === item.label 
                ? "bg-blue-600/10 text-blue-400 border border-blue-500/10 shadow-[inset_0_0_15px_rgba(59,130,246,0.05)]"
                : "text-slate-400 hover:bg-slate-900/50 hover:text-slate-200"
              )}
            >
              <item.icon className={cn("w-4 h-4", activeSection === item.label ? "text-blue-400" : "text-slate-500")} />
              {item.label}
            </button>
          ))}
        </div>

        <div className="md:col-span-9">
          <Card className="bg-slate-900/50 border-slate-800 backdrop-blur-sm overflow-hidden">
            <CardHeader className="border-b border-slate-800/50 bg-slate-900/30">
              <CardTitle className="text-lg flex items-center gap-2">
                <Sliders className="w-4 h-4 text-blue-500" />
                {activeSection}
              </CardTitle>
              <CardDescription>
                {activeSection === 'Security Policies' && 'Configure detection engine sensitivity and active monitoring modules.'}
                {activeSection === 'Profile Settings' && 'Modify the system user/researcher identity details.'}
                {activeSection === 'Alert Notifications' && 'Set custom notification parameters, SIEM integrations, and siren audio warnings.'}
                {activeSection === 'Display Interface' && 'Customize visualization parameters, refresh interval rate, and layout densities.'}
                {activeSection === 'API Keys' && 'Configure and view API credentials for raw alert/flow log ingestion.'}
                {activeSection === 'Documentation' && 'Reference guide for hybrid ML architecture details and feature vectors.'}
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-8 space-y-10">
              {renderSectionContent()}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}