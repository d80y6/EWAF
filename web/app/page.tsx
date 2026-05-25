"use client";

import React, { useState, useEffect, ReactNode } from 'react';
import { Shield, AlertTriangle, Activity, List, BarChart3, Globe, Users, Cpu, BrainCircuit, TrendingUp } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

const mockChartData = [
  { name: '00:00', requests: 400, blocked: 24 },
  { name: '04:00', requests: 300, blocked: 18 },
  { name: '08:00', requests: 900, blocked: 120 },
  { name: '12:00', requests: 1200, blocked: 240 },
  { name: '16:00', requests: 1500, blocked: 310 },
  { name: '20:00', requests: 1100, blocked: 180 },
  { name: '23:59', requests: 800, blocked: 90 },
];

interface Rule {
  ID: string;
  Name: string;
  Category?: string;
  Action: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalRequests: 0,
    blockedRequests: 0,
    threatLevel: 'Unknown',
    mlAnomalies: 0,
    apiViolations: 0,
    maliciousIPs: 1240,
    activeTenants: 12,
    aiRules: 4,
    wasmPlugins: 2,
  });

  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8081';
    const fetchData = async () => {
      try {
        const statsResp = await fetch(`${apiUrl}/api/stats`);
        const statsData = await statsResp.json();
        setStats(prev => ({ ...prev, ...statsData }));

        const rulesResp = await fetch(`${apiUrl}/api/rules`);
        const rulesData = await rulesResp.json();
        setRules(rulesData);
      } catch (error) {
        console.error("Failed to fetch data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-8">
      <header className="flex items-center justify-between mb-12">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Overview</h1>
          <p className="text-slate-400 mt-1">Real-time threat monitoring and system status.</p>
        </div>
        <div className="flex items-center gap-4">
          <span className="bg-emerald-500/10 text-emerald-500 px-3 py-1 rounded-full text-sm font-medium border border-emerald-500/20 flex items-center gap-2">
            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            System Online
          </span>
        </div>
      </header>

      <main className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-8 gap-6 mb-12">
        <StatCard
          title="Total Requests"
          value={stats.totalRequests.toLocaleString()}
          icon={<Activity className="w-5 h-5 text-indigo-400" />}
        />
        <StatCard
          title="Blocked Requests"
          value={stats.blockedRequests.toLocaleString()}
          icon={<AlertTriangle className="w-5 h-5 text-rose-400" />}
          critical
        />
        <StatCard
          title="ML Anomalies"
          value={stats.mlAnomalies.toLocaleString()}
          icon={<BarChart3 className="w-5 h-5 text-amber-400" />}
        />
        <StatCard
          title="API Violations"
          value={stats.apiViolations.toLocaleString()}
          icon={<List className="w-5 h-5 text-violet-400" />}
        />
        <StatCard
          title="Malicious IPs"
          value={stats.maliciousIPs.toLocaleString()}
          icon={<Globe className="w-5 h-5 text-rose-400" />}
        />
        <StatCard
          title="Active Tenants"
          value={stats.activeTenants.toLocaleString()}
          icon={<Users className="w-5 h-5 text-blue-400" />}
        />
        <StatCard
          title="AI Rules"
          value={stats.aiRules.toLocaleString()}
          icon={<BrainCircuit className="w-5 h-5 text-fuchsia-400" />}
        />
        <StatCard
          title="WASM Plugins"
          value={stats.wasmPlugins.toLocaleString()}
          icon={<Cpu className="w-5 h-5 text-cyan-400" />}
        />
      </main>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-12">
        <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
          <div className="flex items-center gap-2 mb-6">
             <TrendingUp className="w-5 h-5 text-indigo-400" />
             <h3 className="font-semibold text-lg">Traffic Distribution</h3>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockChartData}>
                <defs>
                  <linearGradient id="colorReq" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Area type="monotone" dataKey="requests" stroke="#6366f1" fillOpacity={1} fill="url(#colorReq)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
           <div className="flex items-center gap-2 mb-6">
             <Shield className="w-5 h-5 text-rose-400" />
             <h3 className="font-semibold text-lg">Threat Mitigation</h3>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={mockChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                   contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                   itemStyle={{ color: '#f8fafc' }}
                />
                <Line type="monotone" dataKey="blocked" stroke="#f43f5e" strokeWidth={2} dot={{ fill: '#f43f5e' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <section className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <List className="w-5 h-5 text-indigo-400" />
            <h2 className="text-xl font-semibold">Active Rules</h2>
          </div>
          <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            Add New Rule
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-slate-800/30 text-slate-400 text-sm uppercase tracking-wider">
                <th className="px-6 py-4">ID</th>
                <th className="px-6 py-4">Rule Name</th>
                <th className="px-6 py-4">Category</th>
                <th className="px-6 py-4">Action</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-slate-500">Loading rules...</td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-slate-500">No rules found</td>
                </tr>
              ) : rules.map((rule: Rule) => (
                <tr key={rule.ID} className="hover:bg-slate-800/20 transition-colors">
                  <td className="px-6 py-4 text-slate-500 font-mono text-sm">{rule.ID}</td>
                  <td className="px-6 py-4 font-medium">{rule.Name}</td>
                  <td className="px-6 py-4">
                    <span className="bg-emerald-500/10 text-emerald-500 px-2 py-0.5 rounded text-xs border border-emerald-500/20">
                      {rule.Category}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-0.5 rounded text-xs border ${
                      rule.Action === 'block'
                        ? 'bg-rose-500/10 text-rose-500 border-rose-500/20'
                        : 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                    }`}>
                      {rule.Action}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-slate-400 hover:text-white text-sm transition-colors">Edit</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: string;
  icon: ReactNode;
  critical?: boolean;
}

function StatCard({ title, value, icon, critical = false }: StatCardProps) {
  return (
    <div className="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-slate-400 font-medium">{title}</h3>
        <div className="bg-slate-800/50 p-2 rounded-lg">
          {icon}
        </div>
      </div>
      <div className={`text-4xl font-bold mb-2 ${critical ? 'text-rose-500' : 'text-white'}`}>
        {value}
      </div>
    </div>
  );
}
