import { AlertCircle, CheckCircle2, XCircle, Shield } from "lucide-react";
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
  onRefresh: () => void;
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

export function PremiumRecentThreats({ quarantine, onRefresh }: PremiumRecentThreatsProps) {
  const threats = quarantine.map((f, i) => ({
    id: String(i),
    name: f.filename,
    type: f.threat_type,
    status: "quarantined" as const,
    time: f.date_quarantined,
    severity: (f.threat_type.toLowerCase().includes("virus") || f.threat_type.toLowerCase().includes("critical")) ? "critical" as const : "high" as const,
    path: f.original_path
  }));

  const criticalThreats = threats.filter(t => t.severity === "critical");
  const allThreats = threats;

  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-1">Threat Detection Log</h2>
          <p className="text-gray-600">Latest security threats and actions taken</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          Refresh
        </Button>
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6">
          <TabsTrigger value="all">
            All Threats ({allThreats.length})
          </TabsTrigger>
          <TabsTrigger value="critical" className="text-red-600">
            <Shield className="w-4 h-4 mr-1" />
            Critical ({criticalThreats.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-0">
          <ScrollArea className="h-[450px] pr-4">
            {allThreats.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-500 py-20">
                <CheckCircle2 className="w-12 h-12 text-green-500 mb-4" />
                <p>No threats detected</p>
              </div>
            ) : (
              <div className="space-y-3">
                {allThreats.map((threat) => {
                  const statusCfg = statusConfig[threat.status];
                  const severityCfg = severityConfig[threat.severity];
                  const StatusIcon = statusCfg.icon;

                  return (
                    <div
                      key={threat.id}
                      className={`p-5 rounded-xl border-2 ${statusCfg.bgColor} ${statusCfg.borderColor} hover:shadow-lg transition-all cursor-pointer group`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-start gap-3 flex-1">
                          <div className={`p-2 rounded-lg bg-white shadow-sm ${statusCfg.color}`}>
                            <StatusIcon className="w-5 h-5" />
                          </div>
                          <div className="flex-1">
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
                        <Badge
                          variant="outline"
                          className={`${severityCfg.color} ${severityCfg.bgColor} border-0 text-xs font-semibold`}
                        >
                          {severityCfg.label}
                        </Badge>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

        <TabsContent value="critical" className="mt-0">
          <ScrollArea className="h-[450px] pr-4">
            <div className="space-y-3">
              {criticalThreats.map((threat) => {
                const statusCfg = statusConfig[threat.status];
                const StatusIcon = statusCfg.icon;

                return (
                  <div
                    key={threat.id}
                    className={`p-5 rounded-xl border-2 ${statusCfg.bgColor} ${statusCfg.borderColor} hover:shadow-lg transition-all cursor-pointer`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3 flex-1">
                        <div className={`p-2 rounded-lg bg-white shadow-sm ${statusCfg.color}`}>
                          <StatusIcon className="w-5 h-5" />
                        </div>
                        <div className="flex-1">
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
                      <Badge
                        variant="outline"
                        className="text-red-700 bg-red-100 border-0 text-xs font-semibold"
                      >
                        Critical Risk
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </Card>
  );
}

