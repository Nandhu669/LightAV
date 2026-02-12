import { Bell, User, ChevronDown, Shield, ShieldOff } from "lucide-react";
import { Button } from "@/app/components/ui/button";

interface HeaderProps {
  protectionStatus: boolean;
  onToggleProtection: () => void;
}

export function Header({ protectionStatus, onToggleProtection }: HeaderProps) {
  return (
    <header className="bg-white border-b border-gray-200 shadow-sm sticky top-0 z-10">
      <div className="px-8 py-4">
        <div className="flex items-center justify-between">
          {/* Page Title */}
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Security Dashboard</h2>
            <p className="text-sm text-gray-600 mt-0.5">Monitor and manage your security status</p>
          </div>

          {/* Right Side Actions */}
          <div className="flex items-center gap-4">
            {/* Protection Toggle */}
            <Button
              onClick={onToggleProtection}
              variant={protectionStatus ? "default" : "outline"}
              className={`flex items-center gap-2 ${protectionStatus
                ? 'bg-green-600 hover:bg-green-700'
                : 'border-orange-500 text-orange-600 hover:bg-orange-50'
                }`}
            >
              {protectionStatus ? (
                <>
                  <Shield className="w-4 h-4" />
                  <span>Protected</span>
                </>
              ) : (
                <>
                  <ShieldOff className="w-4 h-4" />
                  <span>Paused</span>
                </>
              )}
            </Button>

            {/* Notifications */}
            <button className="relative p-2 hover:bg-gray-100 rounded-lg transition-colors">
              <Bell className="w-5 h-5 text-gray-700" />
            </button>

            {/* User Profile */}
            <Button variant="ghost" className="flex items-center gap-2 hover:bg-gray-100">
              <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center">
                <User className="w-4 h-4 text-white" />
              </div>
              <span className="font-medium text-gray-900">Admin</span>
              <ChevronDown className="w-4 h-4 text-gray-600" />
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}

