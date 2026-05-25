"use client";

import React, { useState, useEffect } from 'react';
import { List, Plus, Search, Trash2, Edit2 } from 'lucide-react';

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8081';
    fetch(`${apiUrl}/api/rules`)
      .then(res => res.json())
      .then(data => {
        setRules(data);
        setLoading(false);
      })
      .catch(err => console.error(err));
  }, []);

  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [simulating, setSimulating] = useState(false);

  const runSimulation = (rule: any) => {
    setSimulating(true);
    fetch('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ rule }),
    })
      .then(res => res.json())
      .then(data => {
        setSimulationResult(data);
        setSimulating(false);
      });
  };

  return (
    <div className="p-8">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">WAF Rules</h1>
          <p className="text-slate-400 mt-1">Manage signature-based detection policies.</p>
        </div>
        <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" /> Create Rule
        </button>
      </header>

      {simulationResult && (
        <div className="mb-8 p-4 bg-indigo-500/10 border border-indigo-500/20 rounded-xl flex items-center justify-between">
          <div>
            <span className="font-bold text-indigo-400">Simulation Report:</span>
            <span className="ml-2 text-slate-300">
               Rule would have matched {simulationResult.matches} requests out of {simulationResult.totalAnalyzed} ({simulationResult.impactPercent.toFixed(2)}% impact).
            </span>
          </div>
          <button onClick={() => setSimulationResult(null)} className="text-slate-400 hover:text-white">Close</button>
        </div>
      )}

      <div className="flex gap-4 mb-6">
        <div className="flex-1 bg-slate-900 border border-slate-800 rounded-lg flex items-center px-4">
          <Search className="w-5 h-5 text-slate-500 mr-2" />
          <input className="bg-transparent border-none focus:ring-0 w-full py-2 text-sm" placeholder="Search rules..." />
        </div>
      </div>

      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-slate-800/30 text-slate-400 text-sm uppercase tracking-wider">
              <th className="px-6 py-4">ID</th>
              <th className="px-6 py-4">Name</th>
              <th className="px-6 py-4">Action</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-slate-500">Loading rules...</td></tr>
            ) : rules.map((rule: any) => (
              <tr key={rule.RuleID || rule.ID} className="hover:bg-slate-800/20 transition-colors">
                <td className="px-6 py-4 font-mono text-xs text-slate-500">{rule.RuleID}</td>
                <td className="px-6 py-4 font-medium">{rule.Name}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-0.5 rounded text-xs border ${
                    rule.Action === 'block' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' : 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                  }`}>
                    {rule.Action}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className="text-sm font-medium">{rule.Score >= 50 ? 'High' : 'Medium'}</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={() => runSimulation(rule)}
                      className="text-xs bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded text-slate-300 transition-colors"
                    >
                      {simulating ? '...' : 'Simulate'}
                    </button>
                    <button className="text-slate-400 hover:text-white transition-colors"><Edit2 className="w-4 h-4" /></button>
                    <button className="text-slate-400 hover:text-rose-500 transition-colors"><Trash2 className="w-4 h-4" /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
