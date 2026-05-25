"use client";

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Plus, Search, Trash2, Edit2 } from 'lucide-react';

interface Rule {
  ID: string;
  RuleID?: string;
  Name: string;
  Action: string;
  Severity?: string;
  Score: number;
  Conditions: Array<{
    Operator: string;
    Target: string;
    Value: string;
  }>;
}

interface SimulationResult {
  matches: number;
  totalAnalyzed: number;
  impactPercent: number;
}

export default function RulesPage() {
  const router = useRouter();
  const [rules, setRules] = useState<Rule[]>([]);
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

  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [simulating, setSimulating] = useState(false);

  const [showModal, setShowModal] = useState(false);
  const [newRule, setNewRule] = useState<Partial<Rule>>({ Name: '', RuleID: '', Action: 'block', Score: 50, Conditions: [{ Operator: 'contains', Target: 'url', Value: '' }] });

  const runSimulation = (rule: Rule) => {
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

  const handleCreateRule = () => {
    fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8081'}/api/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newRule),
    }).then(() => {
      setShowModal(false);
      router.refresh();
      // Fetch rules again to avoid full reload
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8081';
      fetch(`${apiUrl}/api/rules`)
        .then(res => res.json())
        .then(data => setRules(data));
    });
  };

  return (
    <div className="p-8">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">WAF Rules</h1>
          <p className="text-slate-400 mt-1">Manage signature-based detection policies.</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors"
        >
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
            ) : rules.map((rule: Rule) => (
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
                  <span className="text-sm font-medium">{(rule.Score ?? 0) >= 50 ? 'High' : 'Medium'}</span>
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

      {showModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-8 shadow-2xl">
            <h2 className="text-2xl font-bold mb-6">Create New WAF Rule</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-1">Rule Name</label>
                <input
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2"
                  placeholder="e.g. Block SQLi"
                  onChange={e => setNewRule({...newRule, Name: e.target.value})}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Rule ID</label>
                  <input
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 font-mono"
                    placeholder="SQLI_101"
                    onChange={e => setNewRule({...newRule, RuleID: e.target.value})}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-400 mb-1">Action</label>
                  <select
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2"
                    onChange={e => setNewRule({...newRule, Action: e.target.value})}
                  >
                    <option value="block">Block</option>
                    <option value="shadow">Shadow</option>
                    <option value="allow">Allow</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-400 mb-1">Detection Pattern (Regex/Contains)</label>
                <input
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 font-mono"
                  placeholder="UNION SELECT"
                  onChange={e => {
                    const conds = [...(newRule.Conditions || [])];
                    if (conds.length > 0) {
                      conds[0] = { ...conds[0], Value: e.target.value };
                    } else {
                      conds.push({ Operator: 'contains', Target: 'url', Value: e.target.value });
                    }
                    setNewRule({...newRule, Conditions: conds});
                  }}
                />
              </div>
            </div>
            <div className="mt-8 flex justify-end gap-3">
              <button onClick={() => setShowModal(false)} className="px-4 py-2 text-slate-400 hover:text-white transition-colors">Cancel</button>
              <button onClick={handleCreateRule} className="bg-indigo-600 hover:bg-indigo-500 text-white px-6 py-2 rounded-lg font-bold transition-colors">Create Rule</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
