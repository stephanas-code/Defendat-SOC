import React, { useState } from 'react';
import {
  Layers,
  Globe,
  Server,
  ShieldAlert,
  Lock,
  Activity,
  Cpu,
  HardDrive,
  FileWarning,
  Terminal,
} from 'lucide-react';
import { toast } from 'sonner';
import { DiscoveredApp } from '../../types';
import { HostFullStatus, K8sFullStatus, WafFullStatus } from '../../hooks/useNetworkData';
import { Card } from '../ui/card';
import { Button } from '../ui/button';

interface KubernetesSecurityPanelProps {
  k8sStatus: K8sFullStatus | null;
  applications: DiscoveredApp[];
  hostStatus: HostFullStatus | null;
  wafStatus: WafFullStatus | null;
  backendHttp: string;
  onRefresh: () => void;
}

export function KubernetesSecurityPanel({
  k8sStatus,
  applications,
  hostStatus,
  wafStatus,
  backendHttp,
  onRefresh,
}: KubernetesSecurityPanelProps) {
  const [busy, setBusy] = useState(false);

  const handleIsolateWorkload = async (namespace: string, workload: string) => {
    setBusy(true);
    try {
      await fetch(`${backendHttp}/kubernetes/isolate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          namespace,
          workload,
          reason: `Operator-initiated NetworkPolicy quarantine for ${namespace}/${workload}`,
        }),
      });
      toast.warning(`Workload Quarantined: ${namespace}/${workload}`, {
        description: 'Zero-trust Kubernetes NetworkPolicy generated and applied.',
      });
      onRefresh();
    } catch {
      toast.error('Failed to isolate workload');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* 1. Automatic Kubernetes Application & Host Socket Discovery Inventory */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-500/10 rounded-xl border border-blue-500/20">
              <Layers className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">
                Discovered Applications & Active Listening Services ({applications.length})
              </h2>
              <p className="text-xs text-slate-400">
                Real-time inventory from Kubernetes API (/api/v1/services, ingresses, pods) and Linux /proc/net/tcp sockets
              </p>
            </div>
          </div>
          <span
            className={`text-xs font-mono px-3 py-1 rounded-full border ${
              k8sStatus?.connected
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
            }`}
          >
            {k8sStatus?.discovery_mode || 'initializing'}
          </span>
        </div>

        {applications.length === 0 ? (
          <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center text-xs font-mono text-slate-500">
            No Kubernetes services or listening sockets discovered yet. See Settings → Live Server Setup Guide to connect your Kubernetes API or mount /proc.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] font-bold uppercase text-slate-400">
                  <th className="py-3 px-3">Service / App</th>
                  <th className="py-3 px-3">Namespace / Scope</th>
                  <th className="py-3 px-3">Identifier</th>
                  <th className="py-3 px-3">Bind / Ingress</th>
                  <th className="py-3 px-3">Ports</th>
                  <th className="py-3 px-3">Instances</th>
                  <th className="py-3 px-3">Security Status</th>
                  <th className="py-3 px-3">Threats</th>
                  <th className="py-3 px-3 text-right">Containment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {applications.map((app) => (
                  <tr key={app.app_id} className="hover:bg-slate-950/50">
                    <td className="py-3 px-3 font-bold text-white">{app.name}</td>
                    <td className="py-3 px-3 font-mono text-blue-400">{app.namespace}</td>
                    <td className="py-3 px-3 font-mono text-slate-300">{app.service_name}</td>
                    <td className="py-3 px-3 font-mono text-slate-400">{app.ingress_domain}</td>
                    <td className="py-3 px-3 font-mono text-slate-300">{app.exposed_ports.join(', ') || 'internal'}</td>
                    <td className="py-3 px-3 font-mono text-slate-300">{app.pod_count}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                          app.security_status === 'protected'
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : app.security_status === 'isolated'
                            ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                            : 'bg-red-500/15 text-red-400 border border-red-500/30'
                        }`}
                      >
                        {app.security_status}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-orange-400">{app.threat_count}</td>
                    <td className="py-3 px-3 text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy || app.security_status === 'isolated'}
                        onClick={() => handleIsolateWorkload(app.namespace, app.name)}
                        className="text-[10px] h-7 border-slate-700 hover:bg-red-500/15 hover:text-red-400 hover:border-red-500/30 cursor-pointer"
                      >
                        <Lock className="w-3 h-3 mr-1" />
                        {app.security_status === 'isolated' ? 'Isolated' : 'Quarantine'}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* 2. Website, API & OWASP CRS WAF Protection */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-orange-500/10 rounded-xl border border-orange-500/20">
              <Globe className="w-6 h-6 text-orange-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Website, API & OWASP CRS WAF Telemetry</h3>
              <p className="text-xs text-slate-400">
                Live L7 HTTP inspection counters from NGINX Ingress (/waf/auth-verify), /waf/inspect, and WAF_LOG_PATHS
              </p>
            </div>
          </div>
          <span className="text-xs font-mono px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
            Mode: {wafStatus?.mode || 'OWASP_CRS_ACTIVE_PROTECTION'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 mb-6">
          {[
            { label: 'Inspected', val: wafStatus?.total_inspected ?? 0, color: 'text-white' },
            { label: 'Blocked', val: wafStatus?.blocked_requests_count ?? 0, color: 'text-red-400' },
            { label: 'Rate Limited', val: wafStatus?.rate_limited_count ?? 0, color: 'text-amber-400' },
            { label: 'SQL Injection', val: wafStatus?.sqli_count ?? 0, color: 'text-purple-400' },
            { label: 'XSS Attempts', val: wafStatus?.xss_count ?? 0, color: 'text-orange-400' },
            { label: 'Path Traversal', val: wafStatus?.path_traversal_count ?? 0, color: 'text-yellow-400' },
            { label: 'Cmd Injection', val: wafStatus?.command_injection_count ?? 0, color: 'text-red-500' },
            {
              label: 'Brute / Bots',
              val: (wafStatus?.brute_force_count ?? 0) + (wafStatus?.bot_scanner_count ?? 0),
              color: 'text-blue-400',
            },
          ].map((item, i) => (
            <div key={i} className="bg-slate-950/70 border border-slate-800 rounded-xl p-3">
              <p className="text-[10px] text-slate-500 uppercase font-bold">{item.label}</p>
              <p className={`text-xl font-black font-mono mt-1 ${item.color}`}>{item.val}</p>
            </div>
          ))}
        </div>

        {(wafStatus?.recent_detections || []).length === 0 ? (
          <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 text-xs font-mono text-slate-500">
            Zero WAF attacks detected in current session. Configure NGINX Ingress auth-url or WAF_LOG_PATHS (see Settings → Live Server Setup Guide) to inspect incoming HTTP traffic.
          </div>
        ) : (
          <div className="space-y-2 max-h-[240px] overflow-y-auto pr-1">
            {wafStatus?.recent_detections.slice(0, 15).map((d) => (
              <div
                key={d.detection_id}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs"
              >
                <div className="flex items-center gap-2.5 truncate">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 font-bold">
                    {d.rule_id} • {d.action.toUpperCase()}
                  </span>
                  <span className="font-bold text-white">{d.category}</span>
                  <span className="font-mono text-slate-300">{d.src_ip}</span>
                  <span className="font-mono text-slate-400 truncate">
                    {d.method} {d.host}
                    {d.uri}
                  </span>
                </div>
                <span className="text-[10px] font-mono text-slate-500 shrink-0">
                  {new Date(d.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* 3. Kubernetes Cluster Security & Linux Host Telemetry */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-900 border-slate-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-5 h-5 text-blue-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Kubernetes Cluster & Pod Audit</h3>
            </div>
            <span className="text-xs font-mono text-emerald-400 uppercase font-bold">
              {k8sStatus?.nodes_count ?? 0} Nodes • {k8sStatus?.namespaces_count ?? 0} Namespaces • {k8sStatus?.pods_count ?? 0} Pods
            </span>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">
                Suspicious Pods & Runtime Findings ({(k8sStatus?.suspicious_pods || []).length})
              </p>
              {(k8sStatus?.suspicious_pods || []).length === 0 ? (
                <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 text-slate-400 font-mono">
                  No privileged container, root user, or sensitive hostPath violations detected.
                </div>
              ) : (
                <div className="space-y-2">
                  {k8sStatus?.suspicious_pods.map((sp, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-between"
                    >
                      <div>
                        <span className="font-mono font-bold text-white">
                          {sp.namespace}/{sp.pod}
                        </span>
                        <p className="text-red-300 mt-0.5">{sp.issue}</p>
                      </div>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                        {sp.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <p className="text-[10px] text-slate-500 uppercase font-bold mb-2">
                Quarantined Workloads ({(k8sStatus?.isolated_workloads || []).length})
              </p>
              {(k8sStatus?.isolated_workloads || []).length === 0 ? (
                <p className="text-slate-500 font-mono">No workloads currently quarantined via NetworkPolicy.</p>
              ) : (
                <div className="space-y-2">
                  {k8sStatus?.isolated_workloads.map((iso) => (
                    <div
                      key={iso.isolation_id}
                      className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-between"
                    >
                      <span className="font-mono text-purple-300 font-bold">
                        {iso.namespace}/{iso.workload}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">{iso.status}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Card>

        <Card className="bg-slate-900 border-slate-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <Server className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Linux Host Security & File Integrity</h3>
            </div>
            <span className="text-xs font-mono text-emerald-400 uppercase font-bold">
              FIM: {hostStatus?.file_integrity_status || 'verified'} ({hostStatus?.monitored_files_count ?? 0} files)
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs mb-4">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1">
                <Cpu className="w-3 h-3" /> Host CPU
              </p>
              <p className="text-lg font-mono font-bold text-white mt-1">{hostStatus?.cpu_load_pct ?? 0}%</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1">
                <HardDrive className="w-3 h-3" /> Host RAM
              </p>
              <p className="text-lg font-mono font-bold text-white mt-1">
                {hostStatus?.memory_used_pct ?? 0}% ({hostStatus?.memory_used_mb ?? 0}MB)
              </p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1">
                <Activity className="w-3 h-3" /> Active Sockets
              </p>
              <p className="text-lg font-mono font-bold text-white mt-1">{hostStatus?.active_connections ?? 0}</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1">
                <Terminal className="w-3 h-3" /> Processes
              </p>
              <p className="text-lg font-mono font-bold text-white mt-1">{hostStatus?.running_processes ?? 0}</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold flex items-center gap-1">
                <FileWarning className="w-3 h-3" /> SSH Auth Fails
              </p>
              <p className="text-lg font-mono font-bold text-orange-400 mt-1">{hostStatus?.ssh_failed_attempts ?? 0}</p>
            </div>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg">
              <p className="text-[10px] text-slate-500 uppercase font-bold">Net RX / TX</p>
              <p className="text-sm font-mono font-bold text-blue-400 mt-1">
                {hostStatus?.network_rx_mb ?? 0} / {hostStatus?.network_tx_mb ?? 0} MB
              </p>
            </div>
          </div>

          <div className="text-xs space-y-2">
            <div className="p-2.5 bg-slate-950/50 border border-slate-800 rounded-lg font-mono text-slate-300">
              <span className="text-slate-500 uppercase text-[10px] font-bold block mb-1">Listening Host Ports (/proc/net/tcp)</span>
              {(hostStatus?.listening_ports || []).join(', ') || 'None detected'}
            </div>
            {(hostStatus?.unexpected_ports || []).length > 0 && (
              <div className="p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-lg font-mono text-amber-300">
                Unexpected Listening Ports: {hostStatus?.unexpected_ports.join(', ')}
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
