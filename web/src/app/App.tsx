import { useState, useEffect } from "react";
import { Sidebar } from "@/app/components/Sidebar";
import { Header } from "@/app/components/Header";
import { AdvancedSecurityDashboard } from "@/app/components/AdvancedSecurityDashboard";
import { PremiumScanOptions } from "@/app/components/PremiumScanOptions";
import { AdvancedProtection } from "@/app/components/AdvancedProtection";
import { LogReporter } from "@/app/components/LogReporter";
import { PremiumRecentThreats } from "@/app/components/PremiumRecentThreats";
import { EnhancedSystemPerformance } from "@/app/components/EnhancedSystemPerformance";
import { Progress } from "@/app/components/ui/progress";
import { QWebChannel } from '../qwebchannel.js';

// Define qt global for TypeScript
declare global {
    interface Window {
        qt: any;
    }
}

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
    const [pybridge, setPybridge] = useState<any>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [scanProgress, setScanProgress] = useState(0);
    const [scanMessage, setScanMessage] = useState("");
    const [scanHistory, setScanHistory] = useState<any[]>([]);

    // Fetch protection status
    useEffect(() => {
        fetchStatus();
        fetchQuarantine();
        fetchScanHistory();
        const interval = setInterval(() => {
            fetchSystemStats();
        }, 2000);

        // Initialize Native Bridge
        const initBridge = (retries = 5) => {
            if (typeof window.qt !== 'undefined') {
                new QWebChannel(window.qt.webChannelTransport, (channel: any) => {
                    const bridge = channel.objects.pybridge;
                    setPybridge(bridge);
                    bridge.log('Native bridge connected to Premium UI');
                });
            } else if (retries > 0) {
                setTimeout(() => initBridge(retries - 1), 500);
            }
        };
        initBridge();

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

    const fetchScanHistory = async () => {
        try {
            const res = await fetch('/api/scan_history');
            const data = await res.json();
            setScanHistory(data.history || []);
        } catch (error) {
            console.error('Failed to fetch scan history:', error);
        }
    };

    const startScan = async (path: string) => {
        setIsScanning(true);
        setScanProgress(0);
        setScanMessage(`Scanning ${path}...`);

        // Simulate progress for better UX
        const interval = setInterval(() => {
            setScanProgress(prev => (prev < 90 ? prev + 5 : prev));
        }, 100);

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path })
            });
            const data = await res.json();
            clearInterval(interval);
            setScanProgress(100);

            if (data.success) {
                setScanMessage(`Scan complete: ${data.verdict}`);
            } else {
                setScanMessage(`Scan failed: ${data.error}`);
            }
            fetchQuarantine();
        } catch (error) {
            clearInterval(interval);
            console.error('Failed to start scan:', error);
            setScanMessage('Failed to connect to scanner');
        } finally {
            setTimeout(() => {
                setIsScanning(false);
                setScanMessage("");
            }, 3000);
        }
    };

    const startFolderScan = async (path: string) => {
        setIsScanning(true);
        setScanProgress(0);
        setScanMessage(`Scanning folder: ${path}...`);

        const interval = setInterval(() => {
            setScanProgress(prev => (prev < 95 ? prev + 2 : prev));
        }, 200);

        try {
            const res = await fetch('/api/scan_folder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path })
            });
            const data = await res.json();
            clearInterval(interval);
            setScanProgress(100);

            if (data.success) {
                setScanMessage(`Folder scan complete. Found ${data.threats_found} threats.`);
            } else {
                setScanMessage(`Folder scan failed: ${data.error}`);
            }
            fetchQuarantine();
        } catch (error) {
            clearInterval(interval);
            console.error('Failed to start folder scan:', error);
            setScanMessage('Failed to connect to scanner');
        } finally {
            setTimeout(() => {
                setIsScanning(false);
                setScanMessage("");
            }, 3000);
        }
    };

    const startFullScan = async () => {
        setIsScanning(true);
        setScanProgress(0);
        setScanMessage("Requesting Full System Scan...");

        try {
            const res = await fetch('/api/full_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const startData = await res.json();

            if (!startData.success) {
                setScanMessage(`Failed to start scan: ${startData.error}`);
                setIsScanning(false);
                return;
            }

            const jobId = startData.job_id;
            setScanMessage("Scan initialized. Starting traversal...");

            // Polling interval
            const pollInterval = setInterval(async () => {
                try {
                    const statusRes = await fetch(`/api/scan_status/${jobId}`);
                    const statusData = await statusRes.json();

                    if (!statusData.success) {
                        setScanMessage("Lost connection to scan job.");
                        clearInterval(pollInterval);
                        setIsScanning(false);
                        return;
                    }

                    if (statusData.status === "running") {
                        // Truncate path if too long for UI
                        const displayPath = statusData.last_file.length > 50
                            ? "..." + statusData.last_file.slice(-47)
                            : statusData.last_file;

                        setScanMessage(`Scanning: ${statusData.files_scanned.toLocaleString()} files processed.\n${displayPath}`);

                        // Slowly move progress towards 99% based on activity, never loop back
                        setScanProgress(prev => (prev < 99 ? prev + 0.5 : 99));
                    } else if (statusData.status === "completed") {
                        clearInterval(pollInterval);
                        setScanProgress(100);
                        setScanMessage(`Full System Scan complete. Scanned ${statusData.scanned_paths?.join(', ')}. Found ${statusData.threat_found} threats.`);
                        fetchQuarantine();
                        setTimeout(() => {
                            setIsScanning(false);
                            setScanMessage("");
                        }, 5000);
                    } else if (statusData.status === "halted") {
                        clearInterval(pollInterval);
                        setScanProgress(100);
                        setScanMessage(statusData.message);
                        fetchQuarantine();
                        setTimeout(() => {
                            setIsScanning(false);
                            setScanMessage("");
                        }, 5000);
                    } else if (statusData.status === "failed") {
                        clearInterval(pollInterval);
                        setScanMessage(`Scan failed: ${statusData.message}`);
                        setIsScanning(false);
                    }
                } catch (err) {
                    console.error("Polling error:", err);
                }
            }, 1000);

        } catch (error) {
            console.error('Failed to connect to scanner:', error);
            setScanMessage('Failed to connect to scanner');
            setIsScanning(false);
        }
    };

    const startNetworkScan = async () => {
        setIsScanning(true);
        setScanProgress(0);
        setScanMessage("Starting Network Vulnerability Scan...");

        const interval = setInterval(() => {
            setScanProgress(prev => (prev < 90 ? prev + 10 : prev));
        }, 200);

        try {
            const res = await fetch('/api/network_scan', { method: 'POST' });
            const data = await res.json();
            clearInterval(interval);
            setScanProgress(100);

            if (data.success) {
                setScanMessage(`Network Scan complete. Found ${data.connections.length} active connections.`);
            } else {
                setScanMessage(`Network Scan failed: ${data.error}`);
            }
            fetchScanHistory();
        } catch (error) {
            clearInterval(interval);
            setScanMessage('Failed to connect to scanner');
        } finally {
            setTimeout(() => {
                setIsScanning(false);
                setScanMessage("");
            }, 3000);
        }
    };

    const startVulnerabilityScan = async () => {
        setIsScanning(true);
        setScanProgress(0);
        setScanMessage("Starting System Vulnerability Scan...");

        const interval = setInterval(() => {
            setScanProgress(prev => (prev < 90 ? prev + 15 : prev));
        }, 300);

        try {
            const res = await fetch('/api/vulnerability_scan', { method: 'POST' });
            const data = await res.json();
            clearInterval(interval);
            setScanProgress(100);

            if (data.success) {
                setScanMessage(`Vulnerability Scan complete. Security Score: ${data.score}/100. Found ${data.vulnerabilities.length} issues.`);
            } else {
                setScanMessage(`Vulnerability Scan failed: ${data.error}`);
            }
            fetchScanHistory();
        } catch (error) {
            clearInterval(interval);
            setScanMessage('Failed to connect to scanner');
        } finally {
            setTimeout(() => {
                setIsScanning(false);
                setScanMessage("");
            }, 3000);
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
            <Sidebar
                activeTab={activeTab}
                onTabChange={setActiveTab}
                protectionStatus={status.running}
            />

            {/* Main Content Area */}
            <div className="ml-64">
                <Header
                    protectionStatus={status.running}
                    onToggleProtection={toggleProtection}
                />

                <main className="p-8">
                    {isScanning && (
                        <div className="mb-8 p-6 bg-white rounded-xl border border-blue-200 shadow-sm animate-in fade-in slide-in-from-top-4">
                            <div className="flex justify-between items-center mb-4">
                                <h3 className="font-semibold text-gray-900 whitespace-pre-line">{scanMessage}</h3>
                                <span className="text-sm font-medium text-blue-600">{scanProgress}%</span>
                            </div>
                            <Progress value={scanProgress} className="h-2" />
                        </div>
                    )}

                    {!isScanning && scanMessage && (
                        <div className="mb-8 p-6 bg-green-50 rounded-xl border border-green-200 shadow-sm">
                            <h3 className="font-semibold text-green-900">{scanMessage}</h3>
                        </div>
                    )}

                    {activeTab === "dashboard" && (
                        <div className="space-y-8">
                            {/* Hero Status Cards */}
                            <AdvancedSecurityDashboard
                                protectionStatus={status.running}
                                systemStats={systemStats}
                                quarantineCount={quarantine.length}
                            />

                            {/* Scan Options */}
                            <PremiumScanOptions
                                onScan={startScan}
                                onFolderScan={startFolderScan}
                                onFullScan={startFullScan}
                                onNetworkScan={startNetworkScan}
                                onVulnerabilityScan={startVulnerabilityScan}
                                pybridge={pybridge}
                            />

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
                                    <LogReporter />
                                </div>
                                <div className="lg:col-span-2">
                                    <PremiumRecentThreats
                                        quarantine={quarantine}
                                        scanHistory={scanHistory}
                                        onRefresh={() => {
                                            fetchQuarantine();
                                            fetchScanHistory();
                                        }}
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === "scan" && (
                        <div className="space-y-8">
                            <PremiumScanOptions
                                onScan={startScan}
                                onFolderScan={startFolderScan}
                                onFullScan={startFullScan}
                                onNetworkScan={startNetworkScan}
                                onVulnerabilityScan={startVulnerabilityScan}
                                pybridge={pybridge}
                            />
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
                                scanHistory={scanHistory}
                                onRefresh={() => {
                                    fetchQuarantine();
                                    fetchScanHistory();
                                }}
                            />
                        </div>
                    )}

                    {activeTab === "reports" && (
                        <div className="space-y-8">
                            <LogReporter />
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
