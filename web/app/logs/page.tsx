"use client";

import React, { useState, useEffect } from 'react';
import { ShieldAlert, Search, Filter } from 'lucide-react';

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Mocking logs for now as there's no dedicated logs endpoint yet
    // In a real system, this would fetch from /api/stats/events or similar
    const mockLogs = [
      { id: '1', time: new Date().toISOString(), ip: '192.168.1.50', method: 'POST', url: '/api/login', rule: 'SQL_INJECTION_ATTEMPT', score: 80 },
      { id: '2', time: new Date().toISOString(), ip: '45.78.12.3', method: 'GET', url: '/etc/passwd', rule: 'PATH_TRAVERSAL', score: 100 },
      { id: '3', time: new Date().toISOString(), ip: '10.0.0.15', method: 'POST', url: '/graphql', rule: 'GRAPHQL_COMPLEXITY_EXCEEDED', score: 40 },
    ];
    setLogs(mockLogs as any);
    setLoading(false);
  }, []);

  return (
    <div className="p-8">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Events</h1>
          <p className="text-slate-400 mt-1">Detailed log of blocked and suspicious requests.</p>
        </div>
      </header>

      <div className="flex gap-4 mb-6">
        <div className="flex-1 bg-slate-900 border border-slate-800 rounded-lg flex items-center px-4">
          <Search className="w-5 h-5 text-slate-500 mr-2" />
          <input className="bg-transparent border-none focus:ring-0 w-full py-2 text-sm" placeholder="Search by IP, URL, or Rule..." />
        </div>
        <button className="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors">
          <Filter className="w-4 h-4" /> Filter
        </button>
      </div>

      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-slate-800/30 text-slate-400 text-sm uppercase tracking-wider">
              <th className="px-6 py-4">Timestamp</th>
              <th className="px-6 py-4">Source IP</th>
              <th className="px-6 py-4">Request</th>
              <th className="px-6 py-4">Matched Rule</th>
              <th className="px-6 py-4 text-right">Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-slate-500">Loading events...</td></tr>
            ) : logs.map((log: any) => (
              <tr key={log.id} className="hover:bg-slate-800/20 transition-colors">
                <td className="px-6 py-4 text-sm text-slate-400">{new Date(log.time).toLocaleString()}</td>
                <td className="px-6 py-4 font-mono text-sm">{log.ip}</td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-slate-800">{log.method}</span>
                    <span className="text-sm truncate max-w-xs">{log.url}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                   <span className="bg-rose-500/10 text-rose-500 px-2 py-0.5 rounded text-xs border border-rose-500/20">
                      {log.rule}
                    </span>
                </td>
                <td className="px-6 py-4 text-right font-bold text-rose-500">{log.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
