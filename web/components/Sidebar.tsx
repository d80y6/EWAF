import React from 'react';
import Link from 'next/link';
import { Shield, LayoutDashboard, List, ShieldAlert, Settings } from 'lucide-react';

export default function Sidebar() {
  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
      <div className="p-6 flex items-center gap-3 border-b border-slate-800">
        <Shield className="w-8 h-8 text-indigo-500" />
        <span className="text-xl font-bold tracking-tight">Sentinel</span>
      </div>
      <nav className="flex-1 p-4 space-y-2">
        <NavItem href="/" icon={<LayoutDashboard size={20} />} label="Dashboard" />
        <NavItem href="/logs" icon={<ShieldAlert size={20} />} label="Security Events" />
        <NavItem href="/rules" icon={<List size={20} />} label="WAF Rules" />
        <NavItem href="/settings" icon={<Settings size={20} />} label="Settings" />
      </nav>
    </div>
  );
}

function NavItem({ href, icon, label }: { href: string, icon: React.ReactNode, label: string }) {
  return (
    <Link href={href} className="flex items-center gap-3 px-4 py-3 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors">
      {icon}
      <span className="font-medium">{label}</span>
    </Link>
  );
}
