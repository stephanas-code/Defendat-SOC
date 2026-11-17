import React, { useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  Bell,
  User,
  Monitor,
  Key,
  BookOpen,
  Save,
  Sliders,
  Zap,
  Copy,
  Check,
  Volume2,
  VolumeX,
  Eye,
  EyeOff,
  Terminal,
  Server,
  Layers,
  Lock,
} from 'lucide-react';
import { toast } from 'sonner';
import { Switch } from '../ui/switch';
import { Label } from '../ui/label';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { cn } from '@/lib/utils';

const DEFAULT_MODULES = [
  { id: 'dpi', label: 'OWASP CRS WAF & HTTP Inspection', enabled: true },
  { id: 'flow', label: '44-Feature AI Flow Anomaly Engine', enabled: true },
  { id: 'k8s', label: 'Kubernetes Auto-Discovery & Audit', enabled: true },
  { id: 'host', label: 'Linux Host & Log Monitor', enabled: true },
  { id: 'idp', label: 'Automated Intrusion Prevention (IDP)', enabled: true },
  { id: 'geoip', label: 'Geo-IP & Threat Correlation Engine', enabled: true },
];

export function SettingsPage() {
  const [activeSection, setActiveSection] = React.useState('Live Server Setup Guide');
  const [isSaving, setIsSaving] = React.useState(false);
  const [copiedBlock, setCopiedBlock] = React.useState<string | null>(null);
  const [showKey, setShowKey] = React.useState(false);

  const backendHttp =
    ((import.meta.env.VITE_BACKEND_HTTP as string | undefined) || 'http://localhost:8000').replace(/\/+$/, '');

  const [sensitivity, setSensitivity] = React.useState<number>(85);
  const [isoThreshold, setIsoThreshold] = React.useState<number>(0.65);
  const [xgbThreshold, setXgbThreshold] = React.useState<number>(0.70);
  const [idpMode, setIdpMode] = React.useState<string>('safe_enforce');
  const [modules, setModules] = React.useState(DEFAULT_MODULES);

  const [profile, setProfile] = React.useState(() => {
    try {
      const saved = localStorage.getItem('nids_profile');
      if (saved) return JSON.parse(saved);
    } catch {
      // ignore
    }
    return {
      name: 'Stephanas Odogu',
      email: 'admin@security.local',
      role: 'SOC Administrator',
      institution: 'MIVA Open University',
    };
  });

  const [notifications, setNotifications] = React.useState(() => {
    try {
      const saved = localStorage.getItem('nids_notifications');
      if (saved) return JSON.parse(saved);
    } catch {
      // ignore
    }
    return {
      emailAlerts: false,
      pushNotifications: true,
      soundEnabled: localStorage.getItem('nids_sound_enabled') !== 'false',
      slackWebhook: '',
    };
  });

  const [display, setDisplay] = React.useState(() => {
    try {
      const saved = localStorage.getItem('nids_display');
      if (saved) return JSON.parse(saved);
    } catch {
      // ignore
    }
    return {
      compactMode: false,
      refreshRate: '5',
    };
  });

  const apiKey = 'nids_live_ak_7a8b9c1d2e3f4g5h6i7j8k9l0m1n2o3p';

  // Fetch real runtime settings from backend on mount
  useEffect(() => {
    let active = true;
    fetch(`${backendHttp}/settings`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!active || !data) return;
        if (typeof data.sensitivity === 'number') setSensitivity(data.sensitivity);
        if (typeof data.isoforest_threshold === 'number') setIsoThreshold(data.isoforest_threshold);
        if (typeof data.xgboost_confidence_threshold === 'number') setXgbThreshold(data.xgboost_confidence_threshold);
        if (typeof data.idp_enforcement_mode === 'string') setIdpMode(data.idp_enforcement_mode);
        if (Array.isArray(data.modules)) setModules(data.modules);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [backendHttp]);

  const toggleModule = (id: string) => {
    setModules((prev) => prev.map((mod) => (mod.id === id ? { ...mod, enabled: !mod.enabled } : mod)));
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      localStorage.setItem('nids_profile', JSON.stringify(profile));
      localStorage.setItem('nids_notifications', JSON.stringify(notifications));
      localStorage.setItem('nids_sound_enabled', notifications.soundEnabled.toString());
      localStorage.setItem('nids_display', JSON.stringify(display));

      const res = await fetch(`${backendHttp}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sensitivity,
          modules,
          notifications,
          display,
          idp_enforcement_mode: idpMode,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data?.settings) {
          setIsoThreshold(data.settings.isoforest_threshold);
          setXgbThreshold(data.settings.xgboost_confidence_threshold);
        }
      }
      toast.success('Live Backend Configuration Saved', {
        description: 'Thresholds, active modules, and IDP policies synchronized with backend.',
      });
    } catch {
      toast.error('Failed to save configuration to backend');
    } finally {
      setIsSaving(false);
    }
  };

  const copyText = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedBlock(id);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopiedBlock(null), 2000);
  };

  const sections = [
    { icon: BookOpen, label: 'Live Server Setup Guide' },
    { icon: Shield, label: 'Security Policies' },
    { icon: Bell, label: 'Alert Notifications' },
    { icon: Monitor, label: 'Display Interface' },
    { icon: Key, label: 'API Keys' },
    { icon: User, label: 'Operator Identity' },
  ];

  const CodeSnippet = ({ id, title, code }: { id: string; title: string; code: string }) => (
    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-slate-900/70 border-b border-slate-800">
        <span className="text-[11px] font-mono font-bold text-slate-300 flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          {title}
        </span>
        <button
          onClick={() => copyText(id, code)}
          className="text-xs font-mono text-slate-400 hover:text-white flex items-center gap-1 cursor-pointer"
        >
          {copiedBlock === id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          {copiedBlock === id ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">{code}</pre>
    </div>
  );

  const renderSectionContent = () => {
    switch (activeSection) {
      case 'Live Server Setup Guide':
        return (
          <div className="space-y-8 max-h-[680px] overflow-y-auto pr-2 custom-scrollbar">
            <div className="p-4 rounded-xl bg-blue-500/10 border border-blue-500/20">
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                Production Linux Server & Kubernetes Setup Documentation
              </h4>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                Follow the steps below to deploy this AI IDS/IDP on a real Linux host or Kubernetes cluster with live packet capture, host telemetry, Kubernetes auto-discovery, OWASP CRS WAF protection, and active firewall prevention.
              </p>
            </div>

            {/* Step 1 */}
            <div className="space-y-3">
              <h4 className="text-sm font-bold text-white">
                Step 1 — Pre-Deployment Server Audit & Firewall Backup (Run on Linux Host)
              </h4>
              <p className="text-xs text-slate-400">
                Before starting active prevention, inspect your network interfaces, identify your administrative SSH IP, and back up your current `iptables`/`nftables` and Kubernetes state:
              </p>
              <CodeSnippet
                id="step1"
                title="Linux Terminal — Pre-Flight Audit & Backup"
                code={`# 1. Clone repository on your Linux / Kubernetes host
git clone https://github.com/stephanas-code/AI-IDS-IDP-TOOL.git
cd AI-IDS-IDP-TOOL

# 2. Check your active network interfaces and admin SSH IP
ip -br addr
who

# 3. Run non-destructive audit & backup (saves to ./backups/YYYYMMDD_HHMMSS/)
chmod +x scripts/pre_deploy_audit.sh scripts/deploy_production.sh scripts/rollback_idp.sh
./scripts/pre_deploy_audit.sh`}
              />
            </div>

            {/* Step 2 */}
            <div className="space-y-3 border-t border-slate-800/80 pt-6">
              <h4 className="text-sm font-bold text-white">
                Step 2 — Configure `.env` for Your Live Server & Protect Your Admin IP
              </h4>
              <p className="text-xs text-slate-400">
                Edit `.env` so your workstation/bastion IP is in `IDP_MANAGEMENT_IPS` and `IDP_ALLOWLIST` (guaranteeing you can never be locked out of SSH or `kubectl`), and set `SENSOR_INTERFACE=any` to capture across host and CNI interfaces:
              </p>
              <CodeSnippet
                id="step2"
                title=".env — Real-Time Server Configuration"
                code={`cp .env.example .env

# Set interface to 'any' (captures eth0 + cni0/flannel/calico with packet deduplication)
SENSOR_INTERFACE=any

# Protect your workstation/bastion IP and Kubernetes CIDRs from ever being blocked
IDP_MANAGEMENT_IPS=127.0.0.1,<YOUR_ADMIN_PUBLIC_IP>
IDP_ALLOWLIST=127.0.0.1/32,::1/128,10.96.0.0/12,10.244.0.0/16,<YOUR_ADMIN_PUBLIC_IP>/32

# Enable IDS + IDP in safe_enforce mode
IDS_ENABLED=true
IDP_ENABLED=true
IDP_ENFORCEMENT_MODE=safe_enforce
IDP_CONFIDENCE_THRESHOLD=0.75
IDP_BLOCK_SECONDS=600`}
              />
            </div>

            {/* Step 3 */}
            <div className="space-y-3 border-t border-slate-800/80 pt-6">
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                <Lock className="w-4 h-4 text-emerald-400" />
                Step 3A — Deploy on Linux Server via Docker Compose (Live Host Capture & IDP)
              </h4>
              <p className="text-xs text-slate-400">
                Starts TimescaleDB, Redis, Kafka, Backend (with `/proc`, `/var/log`, `/etc`, and `/etc/kubernetes/admin.conf` mounted read-only), SOC Dashboard, plus the host-network `sensor` (`CAP_NET_RAW`) and `responder` (`CAP_NET_ADMIN` managing `iptables` chain `AI_IDS_BLOCK`):
              </p>
              <CodeSnippet
                id="step3a"
                title="Docker Compose — Full Live Server Deployment"
                code={`# Start infrastructure, backend, dashboard, live packet sensor, and iptables responder
docker compose --profile capture up -d --build

# Verify all components and ML models are online
curl -s http://localhost:8000/status | python3 -m json.tool

# Verify live packet capture is flushing 44-feature flows to Kafka
docker compose logs -f sensor responder`}
              />
            </div>

            {/* Step 3B */}
            <div className="space-y-3 border-t border-slate-800/80 pt-6">
              <h4 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-400" />
                Step 3B — Deploy Directly Inside Kubernetes Cluster (`k8s/` Manifests)
              </h4>
              <p className="text-xs text-slate-400">
                Deploys the isolated `ai-ids-system` namespace, least-privilege `ClusterRole` (`ai-ids-cluster-auditor`), StatefulSet/Deployments, and the node-level `ai-ids-node-agent` DaemonSet on every Kubernetes node:
              </p>
              <CodeSnippet
                id="step3b"
                title="Kubernetes — Cluster-Wide DaemonSet & Control Plane Deployment"
                code={`# Build local images on the node (or push to your registry)
docker compose --profile capture build

# Apply Kubernetes manifests in order
kubectl apply -f k8s/00-namespace-rbac.yaml
kubectl apply -f k8s/01-config-secrets.yaml
kubectl apply -f k8s/02-storage-db-redis-kafka.yaml
kubectl apply -f k8s/03-backend-dashboard.yaml
kubectl apply -f k8s/04-sensor-responder-daemonset.yaml
kubectl apply -f k8s/05-network-policies-waf.yaml

# Check pod status in ai-ids-system namespace
kubectl get pods -n ai-ids-system -o wide`}
              />
            </div>

            {/* Step 4 */}
            <div className="space-y-3 border-t border-slate-800/80 pt-6">
              <h4 className="text-sm font-bold text-white">
                Step 4 — Connect NGINX Ingress / Websites to the OWASP CRS WAF
              </h4>
              <p className="text-xs text-slate-400">
                Because TLS traffic is encrypted on the wire, L7 HTTP payload inspection (SQLi, XSS, Path Traversal, Command Injection) must occur after TLS termination at your Ingress controller. Add these annotations to any Kubernetes `Ingress` resource to protect it automatically:
              </p>
              <CodeSnippet
                id="step4"
                title="Kubernetes Ingress — External WAF Auth & ModSecurity Annotations"
                code={`metadata:
  annotations:
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/auth-url: "http://ai-ids-backend.ai-ids-system.svc.cluster.local:8000/waf/auth-verify"`}
              />
            </div>

            {/* Step 5 */}
            <div className="space-y-3 border-t border-slate-800/80 pt-6">
              <h4 className="text-sm font-bold text-white">
                Step 5 — Verify Firewall Enforcement & Emergency Rollback Procedure
              </h4>
              <p className="text-xs text-slate-400">
                Inspect active `iptables` blocks on the host or immediately roll back all firewall and `NetworkPolicy` blocks if needed:
              </p>
              <CodeSnippet
                id="step5"
                title="Firewall Verification & Instant Rollback"
                code={`# Inspect active drops in the AI_IDS_BLOCK chain on the Linux host
sudo iptables -L AI_IDS_BLOCK -n -v

# Emergency rollback (flushes AI_IDS_BLOCK & switches IDP to monitor mode without stopping IDS)
./scripts/rollback_idp.sh`}
              />
            </div>
          </div>
        );

      case 'Security Policies':
        return (
          <div className="space-y-8">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                  <Zap className="w-3.5 h-3.5 text-yellow-500" />
                  AI Detection Sensitivity (Synced with Backend)
                </Label>
                <span className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 px-2.5 py-1 rounded">
                  Sensitivity: {sensitivity}% | IsoForest ≥ {isoThreshold} | XGBoost ≥ {xgbThreshold}
                </span>
              </div>
              <input
                type="range"
                className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-blue-500"
                min="1"
                max="100"
                value={sensitivity}
                onChange={(e) => {
                  const s = parseInt(e.target.value, 10);
                  setSensitivity(s);
                  setIsoThreshold(Number((0.95 - (s / 100.0) * 0.35).toFixed(3)));
                  setXgbThreshold(Number(Math.max(0.4, 0.95 - (s / 100.0) * 0.35).toFixed(3)));
                }}
              />
              <div className="flex justify-between text-[10px] text-slate-500 font-mono font-bold uppercase">
                <span>1% Conservative (Low FP)</span>
                <span>50% Balanced</span>
                <span>100% Aggressive</span>
              </div>
            </div>

            <div className="space-y-3">
              <Label className="text-xs font-black text-slate-400 uppercase tracking-widest block">
                IDP Enforcement Mode
              </Label>
              <select
                value={idpMode}
                onChange={(e) => setIdpMode(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm font-mono text-slate-200"
              >
                <option value="safe_enforce">safe_enforce — Host Firewall (iptables/nftables) + OWASP WAF Blocking</option>
                <option value="full_enforce">full_enforce — Host Firewall + WAF + K8s NetworkPolicy Pod Quarantine</option>
                <option value="monitor">monitor — IDS Detection & Logging Only (No Firewall Drops)</option>
              </select>
            </div>

            <div className="space-y-4">
              <Label className="text-xs font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Shield className="w-3.5 h-3.5 text-emerald-500" />
                Active Security Engine Modules
              </Label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {modules.map((mod) => (
                  <div
                    key={mod.id}
                    className={cn(
                      'flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl transition-colors',
                      mod.enabled ? 'ring-1 ring-blue-500/20' : 'opacity-60'
                    )}
                  >
                    <div className="flex flex-col gap-0.5">
                      <span className="text-sm font-bold text-slate-200">{mod.label}</span>
                      <span className="text-[10px] text-slate-500 font-mono">MODULE_ID: {mod.id.toUpperCase()}</span>
                    </div>
                    <Switch checked={mod.enabled} onCheckedChange={() => toggleModule(mod.id)} />
                  </div>
                ))}
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
                    {notifications.soundEnabled ? (
                      <Volume2 className="w-5 h-5 text-yellow-500" />
                    ) : (
                      <VolumeX className="w-5 h-5 text-slate-500" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-200">Audible Intrusion Siren</p>
                    <p className="text-xs text-slate-500">Play audio warning when Critical or High threats arrive over WebSocket.</p>
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
                    <p className="text-sm font-bold text-slate-200">Toast Notifications</p>
                    <p className="text-xs text-slate-500">Display real-time alert banners in the SOC interface.</p>
                  </div>
                </div>
                <Switch
                  checked={notifications.pushNotifications}
                  onCheckedChange={(val) => setNotifications({ ...notifications, pushNotifications: val })}
                />
              </div>
            </div>

            <div className="space-y-2 border-t border-slate-800/80 pt-6">
              <Label className="text-xs font-bold text-slate-400">SIEM / Slack Webhook URL</Label>
              <input
                type="text"
                placeholder="https://hooks.slack.com/services/..."
                value={notifications.slackWebhook}
                onChange={(e) => setNotifications({ ...notifications, slackWebhook: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 font-mono"
              />
            </div>
          </div>
        );

      case 'Display Interface':
        return (
          <div className="space-y-6">
            <div className="flex items-center justify-between p-4 bg-slate-950/40 border border-slate-800 rounded-xl">
              <div>
                <p className="text-sm font-bold text-slate-200">Compact Feed Mode</p>
                <p className="text-xs text-slate-500">Reduce vertical padding in live alert streams.</p>
              </div>
              <Switch
                checked={display.compactMode}
                onCheckedChange={(val) => setDisplay({ ...display, compactMode: val })}
              />
            </div>

            <div className="space-y-2">
              <Label className="text-xs font-bold text-slate-400">Telemetry Polling Interval (Seconds)</Label>
              <select
                value={display.refreshRate}
                onChange={(e) => setDisplay({ ...display, refreshRate: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200"
              >
                <option value="5">Standard (5s + Instant WebSocket)</option>
                <option value="10">Reduced (10s)</option>
                <option value="30">Low Bandwidth (30s)</option>
              </select>
            </div>
          </div>
        );

      case 'API Keys':
        return (
          <div className="space-y-6">
            <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-white">X-API-Key Header Credential</p>
                  <p className="text-[10px] text-slate-500 font-mono">Set API_AUTH_ENABLED=true in .env to enforce on admin POST/DELETE endpoints</p>
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
                    onClick={() => copyText('apikey', apiKey)}
                  >
                    {copiedBlock === 'apikey' ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  </Button>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-900 rounded-lg p-3 font-mono text-xs text-slate-300 break-all">
                <span>{showKey ? apiKey : '••••••••••••••••••••••••••••••••••••••••••••••••'}</span>
              </div>
            </div>
          </div>
        );

      case 'Operator Identity':
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <Label className="text-xs font-bold text-slate-400">Administrator Name</Label>
              <input
                type="text"
                value={profile.name}
                onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold text-slate-400">Contact Email</Label>
              <input
                type="email"
                value={profile.email}
                onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold text-slate-400">Role</Label>
              <input
                type="text"
                value={profile.role}
                onChange={(e) => setProfile({ ...profile, role: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs font-bold text-slate-400">Organization</Label>
              <input
                type="text"
                value={profile.institution}
                onChange={(e) => setProfile({ ...profile, institution: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200"
              />
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
          <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/20">
            <SettingsIcon className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white tracking-tight">System Configuration & Live Server Setup</h2>
            <p className="text-slate-400 text-sm font-medium">
              Production setup documentation, live detection thresholds, and IDP enforcement policies
            </p>
          </div>
        </div>
        <Button
          onClick={handleSave}
          disabled={isSaving}
          className="bg-blue-600 hover:bg-blue-700 text-white shadow-lg shadow-blue-900/20 font-bold cursor-pointer"
        >
          {isSaving ? (
            <span className="flex items-center gap-2">
              <Zap className="w-4 h-4 animate-spin" /> Syncing...
            </span>
          ) : (
            <>
              <Save className="w-4 h-4 mr-2" /> Save Configuration
            </>
          )}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        <div className="md:col-span-3 space-y-1">
          {sections.map((item, i) => (
            <button
              key={i}
              onClick={() => setActiveSection(item.label)}
              className={cn(
                'w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all cursor-pointer text-left',
                activeSection === item.label
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-500/10'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200'
              )}
            >
              <item.icon className={cn('w-4 h-4 shrink-0', activeSection === item.label ? 'text-blue-400' : 'text-slate-500')} />
              <span className="truncate">{item.label}</span>
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
                {activeSection === 'Live Server Setup Guide' &&
                  'Complete step-by-step runbook to deploy on a real Linux host and Kubernetes cluster.'}
                {activeSection === 'Security Policies' &&
                  'Configure real-time ML detection sensitivity, active modules, and IDP enforcement mode.'}
                {activeSection === 'Alert Notifications' && 'Configure audible siren and SIEM webhook integration.'}
                {activeSection === 'Display Interface' && 'Customize dashboard refresh interval and layout density.'}
                {activeSection === 'API Keys' && 'View X-API-Key credential for administrative endpoints.'}
                {activeSection === 'Operator Identity' && 'Update SOC administrator contact metadata.'}
              </CardDescription>
            </CardHeader>
            <CardContent className="pt-6">{renderSectionContent()}</CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
