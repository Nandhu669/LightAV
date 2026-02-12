import { useState, useEffect } from "react";
import { Sidebar } from "@/app/components/Sidebar";
import { Header } from "@/app/components/Header";
import { AdvancedSecurityDashboard } from "@/app/components/AdvancedSecurityDashboard";
import { PremiumScanOptions } from "@/app/components/PremiumScanOptions";
import { AdvancedProtection } from "@/app/components/AdvancedProtection";
import { EnhancedThreatActivity } from "@/app/components/EnhancedThreatActivity";
import { PremiumRecentThreats } from "@/app/components/PremiumRecentThreats";
import { EnhancedSystemPerformance } from "@/app/components/EnhancedSystemPerformance";

// Types for LightAV API responses
interface StatusResponse {
    running: boolean;
}

interface SystemStats {
    cpu: number;
    ram: number;
}

interface QuarantineFile {
    filename: string;
    threat_type: string;
    date_quarantined: string;
    quarantine_path: string;
    original_path: string;
}

interface QuarantineResponse {
    files: QuarantineFile[];
}

export default function App() {
    const [activeTab, setActiveTab] = useState("dashboard");
    const [status, setStatus] = useState<StatusResponse>({ running: false });
    const [systemStats, setSystemStats] = useState<SystemStats>({ cpu: 0, ram: 0 });
    const [quarantine, setQuarantine] = useState<QuarantineFile[]>([]);

    // Fetch protection status
    useEffect(() => {
        fetchStatus();
        fetchQuarantine();
        const interval = setInterval(() => {
            fetchSystemStats();
        }, 2000);
        return () => clearInterval(interval);
    }, []);

    const fetchStatus = async () => {
        try {
            const res = await fetch('/api/status');
            const data: StatusResponse = await res.json();
            setStatus(data);
        } catch (error) {
            console.error('Failed to fetch status:', error);
        }
    };

    const fetchSystemStats = async () => {
        try {
            const res = await fetch('/api/system_stats');
            const data: SystemStats = await res.json();
            setSystemStats(data);
        } catch (error) {
            console.error('Failed to fetch system stats:', error);
        }
    };

    const fetchQuarantine = async () => {
        try {
            const res = await fetch('/api/quarantine');
            const data: QuarantineResponse = await res.json();
            setQuarantine(data.files || []);
        } catch (error) {
            console.error('Failed to fetch quarantine:', error);
        }
    };

    const startScan = async (path: string) => {
        try {
            await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path })
            });
            alert(`Scan started for: ${path}`);
            fetchQuarantine(); // Refresh quarantine after scan starts (or wait for completion)
        } catch (error) {
            console.error('Failed to start scan:', error);
        }
    };

    const toggleProtection = async () => {
        try {
            await fetch('/api/toggle', { method: 'POST' });
            fetchStatus();
        } catch (error) {
            console.error('Failed to toggle protection:', error);
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 via-blue-50/30 to-purple-50/30">
            {/* Sidebar */}
            <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

            {/* Main Content Area */}
            <div className="ml-64">
                <Header
                    protectionStatus={status.running}
                    onToggleProtection={toggleProtection}
                />

                <main className="p-8">
                    {activeTab === "dashboard" && (
                        <div className="space-y-8">
                            {/* Hero Status Cards */}
                            <AdvancedSecurityDashboard
                                protectionStatus={status.running}
                                systemStats={systemStats}
                            />

                            {/* Scan Options */}
                            <PremiumScanOptions onScan={startScan} />

                            {/* Protection & Performance Grid */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                <AdvancedProtection
                                    protectionStatus={status.running}
                                    onToggleProtection={toggleProtection}
                                />
                                <EnhancedSystemPerformance
                                    systemStats={systemStats}
                                />
                            </div>

                            {/* Analytics Grid */}
                            <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
                                <div className="lg:col-span-3">
                                    <EnhancedThreatActivity />
                                </div>
                                <div className="lg:col-span-2">
                                    <PremiumRecentThreats
                                        quarantine={quarantine}
                                        onRefresh={fetchQuarantine}
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === "scan" && (
                        <div className="space-y-8">
                            <PremiumScanOptions onScan={startScan} />
                        </div>
                    )}

                    {activeTab === "protection" && (
                        <div className="space-y-8">
                            <AdvancedProtection
                                protectionStatus={status.running}
                                onToggleProtection={toggleProtection}
                            />
                        </div>
                    )}

                    {activeTab === "performance" && (
                        <div className="space-y-8">
                            <EnhancedSystemPerformance
                                systemStats={systemStats}
                            />
                        </div>
                    )}

                    {activeTab === "history" && (
                        <div className="space-y-8">
                            <PremiumRecentThreats
                                quarantine={quarantine}
                                onRefresh={fetchQuarantine}
                            />
                        </div>
                    )}

                    {activeTab === "reports" && (
                        <div className="space-y-8">
                            <EnhancedThreatActivity />
                        </div>
                    )}

                    {activeTab === "settings" && (
                        <div className="space-y-8">
                            <AdvancedProtection
                                protectionStatus={status.running}
                                onToggleProtection={toggleProtection}
                            />
                        </div>
                    )}

                    {activeTab === "help" && (
                        <div className="flex items-center justify-center min-h-[60vh]">
                            <div className="text-center">
                                <h2 className="text-2xl font-bold text-gray-900 mb-2">Help & Support</h2>
                                <p className="text-gray-600">Support features coming soon</p>
                            </div>
                        </div>
                    )}
                </main>

                {/* Footer */}
                <footer className="bg-white/80 backdrop-blur-sm border-t border-gray-200 mt-12">
                    <div className="px-8 py-6">
                        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                            <p className="text-sm text-gray-600">
                                © 2026 LightAV. All rights reserved. | Lightweight Antivirus Solution
                            </p>
                            <div className="flex items-center gap-4 text-sm text-gray-600">
                                <span className="font-semibold">Version 1.0.0</span>
                                <span>•</span>
                                <span>Database: Updated</span>
                                <span>•</span>
                                <span className="flex items-center gap-1.5">
                                    <div className={`w-2 h-2 rounded-full animate-pulse ${status.running ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                                    {status.running ? 'All Systems Operational' : 'Protection Paused'}
                                </span>
                            </div>
                        </div>
                    </div>
                </footer>
            </div>
        </div>
    );
}
