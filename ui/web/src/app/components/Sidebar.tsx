import { Shield, LayoutDashboard, Search, Settings, History, TrendingUp, FileText, HelpCircle } from "lucide-react";
import { cn } from "@/app/components/ui/utils";

interface SidebarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  protectionStatus: boolean;
}

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "scan", label: "Scan", icon: Search },
  { id: "protection", label: "Protection", icon: Shield },
  { id: "performance", label: "Performance", icon: TrendingUp },
  { id: "history", label: "History", icon: History },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "settings", label: "Settings", icon: Settings },
  { id: "help", label: "Help & Support", icon: HelpCircle },
];

export function Sidebar({ activeTab, onTabChange, protectionStatus }: SidebarProps) {
  return (
    <aside className="w-64 bg-gradient-to-b from-slate-900 to-slate-800 text-white min-h-screen fixed left-0 top-0 shadow-2xl">
      {/* Logo */}
      <div className="p-6 border-b border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl shadow-lg">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <div>

            <p className="font-bold italic text-[#ffffff] font-[Castoro] text-justify text-[24px]">Light AV</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="p-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={cn(
                "w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200",
                isActive
                  ? "bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg shadow-blue-500/30"
                  : "text-slate-300 hover:bg-slate-700/50 hover:text-white"
              )}
            >
              <Icon className="w-5 h-5" />
              <span className="font-medium text-sm">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Status Badge */}
      <div className="absolute bottom-6 left-4 right-4">
        <div className={cn(
          "rounded-lg p-4 shadow-lg transition-all duration-300",
          protectionStatus
            ? "bg-gradient-to-r from-green-600 to-emerald-600"
            : "bg-gradient-to-r from-orange-600 to-amber-600"
        )}>
          <div className="flex items-center gap-2 mb-2">
            <div className={cn(
              "w-2 h-2 rounded-full animate-pulse",
              protectionStatus ? "bg-white" : "bg-white/80"
            )}></div>
            <span className="text-sm font-semibold">
              {protectionStatus ? "Protected" : "Paused"}
            </span>
          </div>
          <p className="text-xs text-white/90">
            {protectionStatus ? "All systems secure" : "System unprotected"}
          </p>
        </div>
      </div>
    </aside>
  );
}