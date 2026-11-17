import React from 'react';

export const NAVIGATION_ITEMS = [
  { id: 'overview', label: '1. Overview', badge: 'LIVE' },
  { id: 'ingestion', label: '2. Data Ingestion', badge: 'MOD 1' },
  { id: 'repository', label: '3. Dataset Repository', badge: 'MOD 3' },
  { id: 'normalization', label: '4. Data Normalization', badge: 'MOD 2' },
  { id: 'cases', label: '5. Case Management', badge: 'MOD 4' },
  { id: 'timeline', label: '6. Investigation Timeline', badge: 'MOD 4' },
  { id: 'playbooks', label: '7. Playbook Repository', badge: 'MOD 5' },
  { id: 'quality', label: '8. Data Quality', badge: 'MOD 6' },
  { id: 'process_mining', label: '9. Process Mining', badge: 'FUTURE' },
  { id: 'ai_assessment', label: '10. AI Assessment', badge: 'FUTURE' },
  { id: 'research_analytics', label: '11. Research Analytics', badge: 'FUTURE' },
  { id: 'audit_reports', label: '12. Audit Reports', badge: 'FUTURE' },
  { id: 'settings', label: '13. Settings', badge: 'CFG' },
] as const;

export type NavSectionId = (typeof NAVIGATION_ITEMS)[number]['id'];

interface SidebarLayoutProps {
  activeTab: NavSectionId;
  onSelectTab: (id: NavSectionId) => void;
  children: React.ReactNode;
}

export const SidebarLayout: React.FC<SidebarLayoutProps> = ({
  activeTab,
  onSelectTab,
  children,
}) => {
  return (
    <div className="min-h-screen bg-[#0a0f1d] text-slate-100 flex">
      <aside className="w-72 bg-[#0d1424] border-r border-slate-800 flex flex-col shrink-0">
        <div className="p-5 border-b border-slate-800">
          <div className="text-xs font-mono uppercase tracking-wider text-blue-400">
            SOC-QA INTELLIGENCE
          </div>
          <h1 className="text-sm font-semibold text-slate-100 mt-1">
            Playbook Conformance &amp; Triage QA Workstation
          </h1>
        </div>
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {NAVIGATION_ITEMS.map((item) => (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition ${
                activeTab === item.id
                  ? 'bg-blue-600/20 text-blue-300 border border-blue-500/40'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <span>{item.label}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                {item.badge}
              </span>
            </button>
          ))}
        </nav>
      </aside>
      <main className="flex-1 overflow-y-auto p-6">{children}</main>
    </div>
  );
};
