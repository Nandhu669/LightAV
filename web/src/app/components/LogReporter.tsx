import { useState, useEffect } from "react";
import { Card } from "@/app/components/ui/card";
import { ScrollArea } from "@/app/components/ui/scroll-area";
import { Terminal, Clock, Shield, AlertTriangle, CheckCircle2, RotateCcw } from "lucide-react";
import { Button } from "@/app/components/ui/button";

interface LogEntry {
    id: string;
    timestamp: string;
    event: string;
    status: "info" | "warning" | "success" | "threat";
    module: string;
}

export function LogReporter() {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const fetchLogs = async () => {
        try {
            const res = await fetch('/api/system_logs');
            const data = await res.json();

            if (data.logs) {
                const mappedLogs: LogEntry[] = data.logs.map((raw: any, index: number) => {
                    let status: "info" | "warning" | "success" | "threat" = "info";
                    let event = "";
                    let module = "System";

                    if (raw.action === "quarantine") {
                        status = "threat";
                        event = `Quarantined: ${raw.original}`;
                        module = "Shield";
                    } else if (raw.action === "restore") {
                        status = "success";
                        event = `Restored: ${raw.to}`;
                        module = "Recovery";
                    } else if (raw.verdict !== undefined) {
                        status = raw.verdict === 1 ? "threat" : "success";
                        event = `File Scan: ${raw.file} - ${raw.verdict === 1 ? 'Threat Blocked' : 'Clean'}`;
                        module = raw.source === "cache" ? "HashDB" : "Scanner";
                    }

                    return {
                        id: `log-${index}`,
                        timestamp: new Date(raw.ts).toLocaleString(),
                        event,
                        status,
                        module
                    };
                }).reverse(); // Latest logs first in UI

                setLogs(mappedLogs);
            }
        } catch (error) {
            console.error('Failed to fetch logs:', error);
        } finally {
            setIsLoading(false);
            setIsRefreshing(false);
        }
    };

    const handleRefresh = async () => {
        setIsRefreshing(true);
        await fetchLogs();
    };

    useEffect(() => {
        fetchLogs();
        const interval = setInterval(fetchLogs, 3000);
        return () => clearInterval(interval);
    }, []);

    return (
        <Card className="p-8 h-full min-h-[400px] flex flex-col">
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-slate-900 rounded-lg">
                        <Terminal className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h2 className="text-2xl font-bold text-gray-900 mb-1">System Log Reporter</h2>
                        <p className="text-gray-600">Real-time monitoring and event history</p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRefresh}
                        disabled={isRefreshing}
                        className="gap-2 h-8"
                    >
                        <RotateCcw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                        Refresh
                    </Button>
                    <div className="flex items-center gap-1.5 px-3 py-1 bg-green-50 text-green-700 rounded-full text-xs font-medium border border-green-200">
                        <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
                        Live
                    </div>
                </div>
            </div>

            <div className="border border-gray-200 rounded-xl overflow-hidden flex-1 bg-gray-50/50">
                <div className="grid grid-cols-12 gap-4 px-6 py-3 bg-gray-100 border-b border-gray-200 text-xs font-bold text-gray-500 uppercase tracking-wider">
                    <div className="col-span-3 flex items-center gap-2"><Clock className="w-3 h-3" /> Timestamp</div>
                    <div className="col-span-2 flex items-center gap-2"><Shield className="w-3 h-3" /> Module</div>
                    <div className="col-span-5">Event Description</div>
                    <div className="col-span-2">Status</div>
                </div>

                <ScrollArea className="h-[400px]">
                    <div className="divide-y divide-gray-100">
                        {logs.length === 0 && !isLoading && (
                            <div className="px-6 py-8 text-center text-gray-500 text-sm italic">
                                No logs found. Logs will appear here as system activity occurs.
                            </div>
                        )}
                        {logs.map((log) => (
                            <div key={log.id} className="grid grid-cols-12 gap-4 px-6 py-4 hover:bg-white transition-colors items-center border-l-2 border-l-transparent hover:border-l-blue-500">
                                <div className="col-span-3 font-mono text-xs text-gray-500">
                                    {log.timestamp}
                                </div>
                                <div className="col-span-2">
                                    <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-bold uppercase">
                                        {log.module}
                                    </span>
                                </div>
                                <div className="col-span-5 text-sm font-medium text-gray-700 truncate pr-4" title={log.event}>
                                    {log.event}
                                </div>
                                <div className="col-span-2">
                                    {log.status === "success" && (
                                        <div className="flex items-center gap-1.5 text-green-600">
                                            <CheckCircle2 className="w-3.5 h-3.5" />
                                            <span className="text-xs font-medium">Success</span>
                                        </div>
                                    )}
                                    {log.status === "info" && (
                                        <div className="flex items-center gap-1.5 text-blue-600">
                                            <Clock className="w-3.5 h-3.5" />
                                            <span className="text-xs font-medium">Info</span>
                                        </div>
                                    )}
                                    {log.status === "warning" && (
                                        <div className="flex items-center gap-1.5 text-amber-600">
                                            <AlertTriangle className="w-3.5 h-3.5" />
                                            <span className="text-xs font-medium">Warning</span>
                                        </div>
                                    )}
                                    {log.status === "threat" && (
                                        <div className="flex items-center gap-1.5 text-red-600">
                                            <Shield className="w-3.5 h-3.5" />
                                            <span className="text-xs font-medium uppercase font-bold text-[10px]">Blocked</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </ScrollArea>
            </div>

            <div className="mt-4 flex items-center justify-between text-xs text-gray-400 font-medium">
                <p>Showing last {logs.length} events</p>
                <button className="text-blue-600 hover:underline">Download Report</button>
            </div>
        </Card>
    );
}
