"use client";

import React, { ReactNode } from 'react';
import { Shield, Database, Bell, Key } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="p-8">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">System Settings</h1>
        <p className="text-slate-400 mt-1">Configure global WAF parameters and integrations.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <SettingsSection
          title="General Configuration"
          description="Basic proxy and engine behavior."
          icon={<Shield className="w-5 h-5 text-indigo-400" />}
        >
           <div className="space-y-4">
              <Toggle label="Enable eBPF/XDP Acceleration" checked />
              <Toggle label="Strict Multi-tenancy Mode" checked />
              <div className="space-y-1">
                <label className="text-sm font-medium text-slate-300">Max Request Body Size (MB)</label>
                <input type="number" className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm focus:ring-indigo-500 focus:border-indigo-500" defaultValue={10} />
              </div>
           </div>
        </SettingsSection>

        <SettingsSection
          title="External Integrations"
          description="Connect with SIEM and Auth providers."
          icon={<Database className="w-5 h-5 text-emerald-400" />}
        >
          <div className="space-y-4">
             <div className="space-y-1">
                <label className="text-sm font-medium text-slate-300">PostgreSQL DSN</label>
                <input type="password" title="DSN" className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm" value="postgres://****:****@localhost:5432/sentinel" readOnly />
             </div>
             <div className="space-y-1">
                <label className="text-sm font-medium text-slate-300">NATS Server URL</label>
                <input type="text" className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm" defaultValue="nats://localhost:4222" />
             </div>
          </div>
        </SettingsSection>

        <SettingsSection
          title="API Security & Keys"
          description="Manage JWT secrets and API keys."
          icon={<Key className="w-5 h-5 text-amber-400" />}
        >
           <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-sm font-medium text-slate-300">Default JWT Secret</label>
                <div className="flex gap-2">
                  <input type="password" title="JWT Secret" className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm" value="s3ntinel-p0d-pr0ducti0n-s3cr3t-2025!" readOnly />
                  <button className="bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg text-xs font-medium">Rotate</button>
                </div>
              </div>
           </div>
        </SettingsSection>

        <SettingsSection
          title="Notifications"
          description="Configure how you receive critical alerts."
          icon={<Bell className="w-5 h-5 text-rose-400" />}
        >
          <div className="space-y-4">
             <Toggle label="Email Alerts on High Severity" />
             <Toggle label="Slack Webhook Integration" />
          </div>
        </SettingsSection>
      </div>

      <div className="mt-12 flex justify-end">
        <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg font-medium transition-colors">
          Save Configuration
        </button>
      </div>
    </div>
  );
}

interface SettingsSectionProps {
  title: string;
  description: string;
  icon: ReactNode;
  children: ReactNode;
}

function SettingsSection({ title, description, icon, children }: SettingsSectionProps) {
  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
      <div className="flex items-center gap-3 mb-4">
        <div className="bg-slate-800/50 p-2 rounded-lg">{icon}</div>
        <div>
          <h3 className="font-semibold">{title}</h3>
          <p className="text-xs text-slate-400">{description}</p>
        </div>
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}

interface ToggleProps {
  label: string;
  checked?: boolean;
}

function Toggle({ label, checked = false }: ToggleProps) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-slate-300">{label}</span>
      <div className={`w-10 h-5 rounded-full p-1 transition-colors ${checked ? 'bg-indigo-600' : 'bg-slate-700'}`}>
        <div className={`w-3 h-3 bg-white rounded-full transition-transform ${checked ? 'translate-x-5' : ''}`} />
      </div>
    </div>
  );
}
