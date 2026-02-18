import { useState } from "react";
import { AlertCircle, CheckCircle2, XCircle, Shield, Search, RotateCcw, Loader2 } from "lucide-react";
import { Card } from "@/app/components/ui/card";
import { Badge } from "@/app/components/ui/badge";
import { Button } from "@/app/components/ui/button";
import { ScrollArea } from "@/app/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/app/components/ui/tabs";

interface QuarantineFile {
  filename: string;
  threat_type: string;
  date_quarantined: string;
  quarantine_path: string;
  original_path: string;
}

interface PremiumRecentThreatsProps {
  quarantine: QuarantineFile[];
  scanHistory?: any[];
  onRefresh: () => void;
  onRestoreFile: (quarantinePath: string) => Promise<void>;
}

const statusConfig = {
  blocked: {
    icon: XCircle,
    color: "text-red-600",
    bgColor: "bg-red-50",
    borderColor: "border-red-200",
    badge: "bg-red-600 text-white hover:bg-red-700",
  },
  quarantined: {
    icon: AlertCircle,
    color: "text-amber-600",
    bgColor: "bg-amber-50",
    borderColor: "border-amber-200",
    badge: "bg-amber-600 text-white hover:bg-amber-700",
  },
  removed: {
    icon: CheckCircle2,
    color: "text-green-600",
    bgColor: "bg-green-50",
    borderColor: "border-green-200",
    badge: "bg-green-600 text-white hover:bg-green-700",
  },
};

const severityConfig = {
  critical: {
    color: "text-red-700",
    bgColor: "bg-red-100",
    label: "Critical Risk",
  },
  high: {
    color: "text-orange-700",
    bgColor: "bg-orange-100",
    label: "High Risk",
  },
  medium: {
    color: "text-amber-700",
    bgColor: "bg-amber-100",
    label: "Medium Risk",
  },
  low: {
    color: "text-blue-700",
    bgColor: "bg-blue-100",
    label: "Low Risk",
  },
};

export function PremiumRecentThreats({ quarantine, scanHistory = [], onRefresh, onRestoreFile }: PremiumRecentThreatsProps) {
  const [restoringId, setRestoringId] = useState<string | null>(null);

  const threats = quarantine.map((f, i) => ({
    id: String(i),
    name: f.filename,
    type: f.threat_type,
    status: "quarantined" as const,
    time: f.date_quarantined,
    severity: (f.threat_type.toLowerCase().includes("virus") || f.threat_type.toLowerCase().includes("critical")) ? "critical" as const : "high" as const,
    path: f.original_path,
    quarantine_path: f.quarantine_path,
  }));

  const criticalThreats = threats.filter(t => t.severity === "critical");

  const handleRestore = async (id: string, quarantinePath: string) => {
    setRestoringId(id);
    try {
      await onRestoreFile(quarantinePath);
    } finally {
      setRestoringId(null);
    }
  };

  const ThreatCard = ({ threat, showSeverity = true }: { threat: typeof threats[0]; showSeverity?: boolean }) => {
    const statusCfg = statusConfig[threat.status];
    const severityCfg = severityConfig[threat.severity];
    const StatusIcon = statusCfg.icon;
    const isRestoring = restoringId === threat.id;

    return (
      <div
        key={threat.id}
        className={`p-5 rounded-xl border-2 ${statusCfg.bgColor} ${statusCfg.borderColor} hover:shadow-lg transition-all group`}
      >
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-start gap-3 flex-1">
            <div className={`p-2 rounded-lg bg-white shadow-sm ${statusCfg.color}`}>
              <StatusIcon className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <h4 className="font-bold text-gray-900 mb-1">{threat.name}</h4>
              <p className="text-sm text-gray-700 mb-1">{threat.type}</p>
              <p className="text-xs text-gray-600 font-mono truncate">{threat.path}</p>
            </div>
          </div>
          <Badge className={statusCfg.badge}>
            {threat.status.toUpperCase()}
          </Badge>
        </div>

        <div className="flex items-center justify-between pl-11">
          <span className="text-xs text-gray-600">{threat.time}</span>
          <div className="flex items-center gap-2">
            {showSeverity && (
              <Badge
                variant="outline"
                className={`${severityCfg.color} ${severityCfg.bgColor} border-0 text-xs font-semibold`}
              >
                {severityCfg.label}
              </Badge>
            )}
            {!showSeverity && (
              <Badge
                variant="outline"
                className="text-red-700 bg-red-100 border-0 text-xs font-semibold"
              >
                Critical Risk
              </Badge>
            )}
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs border-amber-300 text-amber-700 hover:bg-amber-100 hover:text-amber-800 hover:border-amber-400 transition-colors"
              disabled={isRestoring}
              onClick={() => handleRestore(threat.id, threat.quarantine_path)}
              title="Restore this file to its original location"
            >
              {isRestoring ? (
                <Loader2 className="w-3 h-3 animate-spin mr-1" />
              ) : (
                <RotateCcw className="w-3 h-3 mr-1" />
              )}
              {isRestoring ? "Restoring…" : "Restore"}
            </Button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-1">Security Activity Log</h2>
          <p className="text-gray-600">Latest threat detections and scan activities</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          Refresh
        </Button>
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6">
          <TabsTrigger value="all">
            Threats ({threats.length})
          </TabsTrigger>
          <TabsTrigger value="history">
            Scan History ({scanHistory.length})
          </TabsTrigger>
          <TabsTrigger value="critical" className="text-red-600">
            <Shield className="w-4 h-4 mr-1" />
            Critical ({criticalThreats.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-0">
          <ScrollArea className="h-[450px] pr-4">
            {threats.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-500 py-20">
                <CheckCircle2 className="w-12 h-12 text-green-500 mb-4" />
                <p>No threats detected</p>
              </div>
            ) : (
              <div className="space-y-3">
                {threats.map((threat) => (
                  <ThreatCard key={threat.id} threat={threat} showSeverity={true} />
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        <TabsContent value="history" className="mt-0">
          <ScrollArea className="h-[450px] pr-4">
            {scanHistory.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-500 py-20">
                <Search className="w-12 h-12 text-blue-500 mb-4 opacity-50" />
                <p>No scan history available</p>
              </div>
            ) : (
              <div className="space-y-3">
                {scanHistory.map((item) => (
                  <div
                    key={item.id}
                    className="p-5 rounded-xl border-2 border-gray-100 bg-gray-50/50 hover:shadow-md transition-all"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-bold text-gray-900 mb-1">{item.type}</h4>
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant="outline" className="text-xs">{item.date}</Badge>
                          <Badge className={item.status === 'Completed' ? 'bg-green-600' : 'bg-red-600'}>
                            {item.status.toUpperCase()}
                          </Badge>
                        </div>
                        {item.results && (
                          <div className="text-xs text-gray-600 space-y-1">
                            {item.results.path && <p>Path: {item.results.path}</p>}
                            {item.results.threats_found !== undefined && (
                              <p className={item.results.threats_found > 0 ? "text-red-600 font-bold" : "text-green-600"}>
                                Threats Found: {item.results.threats_found}
                              </p>
                            )}
                            {item.results.security_score !== undefined && <p>Security Score: {item.results.security_score}/100</p>}
                            {item.results.connections_found !== undefined && <p>Connections Found: {item.results.connections_found}</p>}
                            {item.results.verdict && <p className={item.results.verdict === 'MALICIOUS' ? "text-red-600" : "text-green-600"}>Verdict: {item.results.verdict}</p>}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        <TabsContent value="critical" className="mt-0">
          <ScrollArea className="h-[450px] pr-4">
            {criticalThreats.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-500 py-20">
                <CheckCircle2 className="w-12 h-12 text-green-500 mb-4" />
                <p>No critical threats</p>
              </div>
            ) : (
              <div className="space-y-3">
                {criticalThreats.map((threat) => (
                  <ThreatCard key={threat.id} threat={threat} showSeverity={false} />
                ))}
              </div>
            )}
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </Card>
  );
}
