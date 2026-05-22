/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, Settings, List, BarChart3, Globe, Users } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalRequests: 0,
    blockedRequests: 0,
    threatLevel: 'Unknown',
    mlAnomalies: 0,
    apiViolations: 0,
    maliciousIPs: 1240,
    activeTenants: 12,
  });

  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsResp = await fetch('http://localhost:8081/api/stats');
        const statsData = await statsResp.json();
        setStats(statsData);

        const rulesResp = await fetch('http://localhost:8081/api/rules');
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
    <div className="min-h-screen bg-slate-950 text-slate-50 p-8">
      <header className="flex items-center justify-between mb-12">
        <div className="flex items-center gap-3">
          <Shield className="w-10 h-10 text-indigo-500" />
          <h1 className="text-3xl font-bold tracking-tight">Sentinel WAF</h1>
        </div>
        <div className="flex items-center gap-4">
          <span className="bg-emerald-500/10 text-emerald-500 px-3 py-1 rounded-full text-sm font-medium border border-emerald-500/20">
            System Online
          </span>
          <Settings className="w-6 h-6 text-slate-400 cursor-pointer hover:text-white transition-colors" />
        </div>
      </header>

      <main className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
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
      </main>

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
              ) : rules.map((rule: any) => (
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

function StatCard({ title, value, icon, critical = false }: any) {
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
