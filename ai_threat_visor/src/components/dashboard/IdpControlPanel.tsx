import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Lock,
  Unlock,
  Plus,
  Trash2,
  AlertTriangle,
  Clock,
  Layers,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { toast } from 'sonner';
import { CorrelatedIncident } from '../../types';
import { IdpFullStatus } from '../../hooks/useNetworkData';
import { Card } from '../ui/card';
import { Button } from '../ui/button';

interface IdpControlPanelProps {
  idpStatus: IdpFullStatus | null;
  incidents: CorrelatedIncident[];
  backendHttp: string;
  onRefresh: () => void;
}

export function IdpControlPanel({ idpStatus, incidents, backendHttp, onRefresh }: IdpControlPanelProps) {
  const [blockIpInput, setBlockIpInput] = useState('');
  const [blockReasonInput, setBlockReasonInput] = useState('Confirmed malicious threat actor');
  const [blockDurationInput, setBlockDurationInput] = useState('600');
  const [allowIpInput, setAllowIpInput] = useState('');
  const [allowLabelInput, setAllowLabelInput] = useState('Trusted Admin / Infrastructure');
  const [isMgmtInput, setIsMgmtInput] = useState(false);
  const [busy, setBusy] = useState(false);

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockIpInput.trim()) return;
    setBusy(true);
    try {
      const res = await fetch(`${backendHttp}/idp/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: blockIpInput.trim(),
          reason: blockReasonInput.trim() || 'Manual block',
          severity: 'high',
          duration_seconds: parseInt(blockDurationInput, 10) || 600,
          enforcement_layer: 'iptables',
        }),
      });
      const data = await res.json();
      if (data?.block?.status === 'failed') {
        toast.warning('Safety Guardrail Prevented Block', {
          description: data.block.reason,
        });
      } else {
        toast.success(`IP ${blockIpInput.trim()} Blocked`, {
          description: `Enforced via ${data?.block?.enforcement_layer || 'iptables'}`,
        });
        setBlockIpInput('');
      }
      onRefresh();
    } catch {
      toast.error('Failed to execute manual block');
    } finally {
      setBusy(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    setBusy(true);
    try {
      await fetch(`${backendHttp}/idp/unblock/${encodeURIComponent(ip)}`, { method: 'POST' });
      toast.success(`Unblocked ${ip}`, { description: 'Firewall rule removed and traffic restored.' });
      onRefresh();
    } catch {
      toast.error(`Failed to unblock ${ip}`);
    } finally {
      setBusy(false);
    }
  };

  const handleKillSwitch = async (engage: boolean) => {
    setBusy(true);
    try {
      await fetch(`${backendHttp}/idp/kill-switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engage }),
      });
      if (engage) {
        toast.error('EMERGENCY IDP KILL SWITCH ENGAGED', {
          description: 'All active blocks flushed. System switched to safe IDS Monitor-Only mode.',
        });
      } else {
        toast.success('IDP Active Prevention Re-Armed', {
          description: 'Enforcement mode restored to safe_enforce.',
        });
      }
      onRefresh();
    } catch {
      toast.error('Failed to toggle IDP kill switch');
    } finally {
      setBusy(false);
    }
  };

  const handleModeChange = async (mode: string) => {
    setBusy(true);
    try {
      await fetch(`${backendHttp}/idp/policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: mode !== 'monitor', enforcement_mode: mode }),
      });
      toast.success(`IDP Enforcement Mode set to ${mode.toUpperCase()}`);
      onRefresh();
    } catch {
      toast.error('Failed to update IDP mode');
    } finally {
      setBusy(false);
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!allowIpInput.trim()) return;
    setBusy(true);
    try {
      const res = await fetch(`${backendHttp}/idp/allowlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_or_cidr: allowIpInput.trim(),
          label: allowLabelInput.trim() || 'Trusted IP/CIDR',
          is_management: isMgmtInput,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        toast.error(err.detail || 'Invalid IP/CIDR');
      } else {
        toast.success(`Added ${allowIpInput.trim()} to Protected Allowlist`);
        setAllowIpInput('');
        onRefresh();
      }
    } catch {
      toast.error('Failed to add allowlist entry');
    } finally {
      setBusy(false);
    }
  };

  const handleRemoveAllowlist = async (ipOrCidr: string) => {
    setBusy(true);
    try {
      await fetch(`${backendHttp}/idp/allowlist?ip_or_cidr=${encodeURIComponent(ipOrCidr)}`, {
        method: 'DELETE',
      });
      toast.info(`Removed ${ipOrCidr} from allowlist`);
      onRefresh();
    } catch {
      toast.error('Failed to remove allowlist entry');
    } finally {
      setBusy(false);
    }
  };

  const activeBlocks = idpStatus?.active_blocks || [];
  const historyBlocks = idpStatus?.recent_history || [];
  const allowlist = idpStatus?.allowlist || [];
  const killSwitch = idpStatus?.kill_switch_engaged ?? false;

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Top IDP Banner & Emergency Kill Switch */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-start gap-4">
          <div className={`p-3 rounded-xl border ${killSwitch ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
            {killSwitch ? <ShieldOff className="w-7 h-7 text-red-500" /> : <ShieldCheck className="w-7 h-7 text-emerald-400" />}
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-white">Intrusion Prevention (IDP) & Incident Correlation</h2>
              <span className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full uppercase ${
                killSwitch
                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                  : idpStatus?.enabled
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
              }`}>
                {killSwitch ? 'KILL SWITCH ENGAGED' : `${idpStatus?.enforcement_mode || 'safe_enforce'}`}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Chain: <span className="font-mono text-slate-200">{idpStatus?.chain || 'AI_IDS_BLOCK'}</span> | Confidence Threshold:{' '}
              <span className="font-mono text-slate-200">{((idpStatus?.confidence_threshold ?? 0.75) * 100).toFixed(0)}%</span> | Default TTL:{' '}
              <span className="font-mono text-slate-200">{idpStatus?.block_seconds ?? 600}s</span> | Active Blocks:{' '}
              <span className="font-mono text-emerald-400 font-bold">{activeBlocks.length}</span>
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={idpStatus?.enforcement_mode || 'safe_enforce'}
            onChange={(e) => handleModeChange(e.target.value)}
            disabled={busy}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200"
          >
            <option value="safe_enforce">Mode: SAFE_ENFORCE (Host + WAF)</option>
            <option value="full_enforce">Mode: FULL_ENFORCE (Host + WAF + K8s Isolation)</option>
            <option value="monitor">Mode: MONITOR_ONLY (Dry-Run)</option>
          </select>

          {killSwitch ? (
            <Button
              onClick={() => handleKillSwitch(false)}
              disabled={busy}
              className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs cursor-pointer"
            >
              <ShieldCheck className="w-4 h-4 mr-1.5" />
              Re-Arm IDP Enforcement
            </Button>
          ) : (
            <Button
              onClick={() => handleKillSwitch(true)}
              disabled={busy}
              className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs shadow-lg shadow-red-900/30 cursor-pointer"
            >
              <ShieldOff className="w-4 h-4 mr-1.5" />
              Emergency IDP Kill Switch
            </Button>
          )}
        </div>
      </div>

      {/* Active Blocks & Manual Block Controls */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Card className="xl:col-span-2 bg-slate-900 border-slate-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Currently Blocked Threat Sources ({activeBlocks.length})
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">Auto-expires via TTL Worker</span>
          </div>

          {activeBlocks.length === 0 ? (
            <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs font-mono">
              No IP addresses are currently blocked. Confirmed Critical/High threats meeting confidence threshold will appear here automatically.
            </div>
          ) : (
            <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
              {activeBlocks.map((b) => (
                <div
                  key={b.block_id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-slate-950/70 border border-red-500/20 rounded-xl"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono font-bold text-sm text-white">{b.ip}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 uppercase">
                        {b.status} • {b.enforcement_layer}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-amber-400" />
                        Expires in {b.remaining_seconds ?? 0}s
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{b.reason}</p>
                  </div>
                  <Button
                    onClick={() => handleUnblock(b.ip)}
                    disabled={busy}
                    variant="outline"
                    className="border-slate-700 hover:bg-emerald-500/10 hover:text-emerald-400 hover:border-emerald-500/30 text-xs font-mono shrink-0 cursor-pointer"
                  >
                    <Unlock className="w-3.5 h-3.5 mr-1.5" />
                    Unblock IP
                  </Button>
                </div>
              ))}
            </div>
          )}

          {/* Recent Block History & Safety Guardrail Prevention Log */}
          <div className="mt-6 pt-5 border-t border-slate-800">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
              Prevention Action History & Safety Guardrail Audit ({historyBlocks.length})
            </h4>
            {historyBlocks.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono">No historical unblocks or guardrail rejections yet.</p>
            ) : (
              <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                {historyBlocks.slice(0, 15).map((h) => (
                  <div
                    key={h.block_id}
                    className="flex items-center justify-between text-xs p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/80"
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      {h.status === 'failed' ? (
                        <XCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      )}
                      <span className="font-mono font-bold text-slate-200">{h.ip}</span>
                      <span className="text-slate-400 truncate">{h.reason}</span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase shrink-0 ${
                      h.status === 'failed' ? 'bg-amber-500/10 text-amber-400' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {h.status === 'failed' ? 'GUARDRAIL PROTECTED' : `${h.status} (${h.unblocked_by || 'ttl'})`}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        {/* Manual Block + Allowlist Manager */}
        <div className="space-y-6">
          <Card className="bg-slate-900 border-slate-800 p-5">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              Manual Threat Containment
            </h3>
            <form onSubmit={handleManualBlock} className="space-y-3">
              <input
                type="text"
                placeholder="Malicious IP (e.g. 198.51.100.44)"
                value={blockIpInput}
                onChange={(e) => setBlockIpInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white"
              />
              <input
                type="text"
                placeholder="Block reason"
                value={blockReasonInput}
                onChange={(e) => setBlockReasonInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200"
              />
              <div className="flex gap-2">
                <select
                  value={blockDurationInput}
                  onChange={(e) => setBlockDurationInput(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 flex-1"
                >
                  <option value="60">TTL: 60s (Test)</option>
                  <option value="600">TTL: 10 mins</option>
                  <option value="3600">TTL: 1 hour</option>
                  <option value="86400">TTL: 24 hours</option>
                </select>
                <Button type="submit" disabled={busy} className="bg-red-600 hover:bg-red-700 text-white text-xs font-bold cursor-pointer">
                  Block IP
                </Button>
              </div>
            </form>
          </Card>

          <Card className="bg-slate-900 border-slate-800 p-5">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Protected Allowlist & Management IPs ({allowlist.length})
            </h3>
            <form onSubmit={handleAddAllowlist} className="space-y-2.5 mb-4">
              <input
                type="text"
                placeholder="IP or CIDR (e.g. 203.0.113.5 or 10.244.0.0/16)"
                value={allowIpInput}
                onChange={(e) => setAllowIpInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white"
              />
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Label"
                  value={allowLabelInput}
                  onChange={(e) => setAllowLabelInput(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
                />
                <label className="flex items-center gap-1.5 text-[11px] text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isMgmtInput}
                    onChange={(e) => setIsMgmtInput(e.target.checked)}
                  />
                  Mgmt IP
                </label>
                <Button type="submit" size="sm" disabled={busy} className="bg-blue-600 hover:bg-blue-700 text-white text-xs cursor-pointer">
                  <Plus className="w-3.5 h-3.5" />
                </Button>
              </div>
            </form>
            <div className="space-y-1.5 max-h-[200px] overflow-y-auto pr-1">
              {allowlist.map((entry) => (
                <div
                  key={entry.entry_id}
                  className="flex items-center justify-between text-xs px-2.5 py-1.5 rounded bg-slate-950/60 border border-slate-800"
                >
                  <div>
                    <span className="font-mono font-bold text-emerald-400">{entry.ip_or_cidr}</span>
                    <span className="text-[10px] text-slate-400 ml-2">{entry.label}</span>
                  </div>
                  <button
                    onClick={() => handleRemoveAllowlist(entry.ip_or_cidr)}
                    className="text-slate-500 hover:text-red-400 p-1 cursor-pointer"
                    title="Remove from allowlist"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Centralized Threat Intelligence & Multi-Layer Incident Correlation */}
      <Card className="bg-slate-900 border-slate-800 p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <Layers className="w-5 h-5 text-blue-400" />
            <div>
              <h3 className="text-base font-bold text-white">Centralized Threat Intelligence — Correlated Security Incidents</h3>
              <p className="text-xs text-slate-400">
                Multi-layer event correlation across AI Network Detection, Linux Host Logs, Kubernetes Audit, and OWASP WAF
              </p>
            </div>
          </div>
          <span className="text-xs font-mono font-bold px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
            {incidents.length} Correlated Incidents
          </span>
        </div>

        {incidents.length === 0 ? (
          <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs font-mono">
            No correlated incidents yet. Incoming alerts from Network, Host, Kubernetes, and WAF are automatically correlated here by threat actor & target workload.
          </div>
        ) : (
          <div className="space-y-3">
            {incidents.slice(0, 20).map((inc) => (
              <div
                key={inc.incident_id}
                className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition-all"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="font-mono text-xs font-black px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
                      {inc.incident_id}
                    </span>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                      inc.severity === 'critical'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : inc.severity === 'high'
                        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                        : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                    }`}>
                      {inc.severity} ({(inc.confidence * 100).toFixed(0)}% conf)
                    </span>
                    <h4 className="text-sm font-bold text-white">{inc.title}</h4>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {inc.response_status}
                    </span>
                    <span className="text-slate-500">{inc.event_count} events</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs mt-3 pt-3 border-t border-slate-800/70">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Source Actor → Target</span>
                    <span className="font-mono text-slate-200">{inc.src_ip} → {inc.dst_ip}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Target App / Namespace</span>
                    <span className="font-mono text-slate-200">{inc.target_app || 'cluster-wide'} ({inc.target_namespace || 'default'})</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">Correlated Detection Layers</span>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {inc.detection_sources.map((src, idx) => (
                        <span key={idx} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-blue-300">
                          {src}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-bold block">IDP Prevention Action</span>
                    <span className="font-mono text-emerald-400">{inc.prevention_action}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
