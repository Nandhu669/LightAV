import { Card } from "@/app/components/ui/card";
import { Progress } from "@/app/components/ui/progress";
import { Badge } from "@/app/components/ui/badge";
import { Cpu, HardDrive, Activity, Zap, Gauge } from "lucide-react";
import { LineChart, Line, ResponsiveContainer } from "recharts";

interface PerformanceMetric {
  id: string;
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  gradient: string;
  unit: string;
  status: "optimal" | "good" | "warning";
  sparklineData: number[];
}

interface EnhancedSystemPerformanceProps {
  systemStats: {
    cpu: number;
    ram: number;
  };
}

const statusConfig = {
  optimal: {
    label: "Optimal",
    color: "text-green-700",
    bgColor: "bg-green-100",
  },
  good: {
    label: "Good",
    color: "text-blue-700",
    bgColor: "bg-blue-100",
  },
  warning: {
    label: "Attention",
    color: "text-amber-700",
    bgColor: "bg-amber-100",
  },
};

export function EnhancedSystemPerformance({ systemStats }: EnhancedSystemPerformanceProps) {
  const metrics: PerformanceMetric[] = [
    {
      id: "cpu",
      label: "CPU Usage",
      value: systemStats.cpu,
      icon: Cpu,
      color: "text-blue-600",
      gradient: "from-blue-500 to-cyan-500",
      unit: "%",
      status: systemStats.cpu < 50 ? "optimal" : systemStats.cpu < 80 ? "good" : "warning",
      sparklineData: [15, 18, 22, 19, 25, 23, 20, systemStats.cpu],
    },
    {
      id: "memory",
      label: "Memory Usage",
      value: systemStats.ram,
      icon: Activity,
      color: "text-purple-600",
      gradient: "from-purple-500 to-pink-500",
      unit: "%",
      status: systemStats.ram < 60 ? "optimal" : systemStats.ram < 85 ? "good" : "warning",
      sparklineData: [40, 42, 44, 43, 46, 45, 44, systemStats.ram],
    },
    {
      id: "disk",
      label: "Disk I/O",
      value: 12,
      icon: HardDrive,
      color: "text-green-600",
      gradient: "from-green-500 to-emerald-500",
      unit: "%",
      status: "optimal",
      sparklineData: [30, 28, 35, 32, 34, 31, 33, 32],
    },
    {
      id: "protection",
      label: "Protection Impact",
      value: 5,
      icon: Zap,
      color: "text-amber-600",
      gradient: "from-amber-500 to-orange-500",
      unit: "%",
      status: "optimal",
      sparklineData: [10, 12, 11, 13, 12, 11, 12, 12],
    },
  ];

  const overallScore = 100 - Math.round((systemStats.cpu + systemStats.ram) / 4);

  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-1">System Performance</h2>
          <p className="text-gray-600">Real-time resource monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-sm text-gray-600 mb-1">Performance Score</p>
            <p className="text-2xl font-bold text-green-600">{overallScore}</p>
          </div>
          <div className="p-3 bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl">
            <Gauge className="w-6 h-6 text-white" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {metrics.map((metric) => {
          const Icon = metric.icon;
          const statusCfg = statusConfig[metric.status];
          const sparklineChartData = metric.sparklineData.map((value, index) => ({
            value,
            index
          }));

          return (
            <div key={metric.id} className="p-5 bg-gray-50 rounded-xl border border-gray-200">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`p-3 bg-gradient-to-br ${metric.gradient} rounded-lg shadow-lg`}>
                    <Icon className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <p className="font-semibold text-gray-900">{metric.label}</p>
                    <Badge
                      variant="outline"
                      className={`${statusCfg.color} ${statusCfg.bgColor} border-0 text-xs mt-1`}
                    >
                      {statusCfg.label}
                    </Badge>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold text-gray-900">{metric.value.toFixed(1)}{metric.unit}</p>
                </div>
              </div>

              <Progress value={metric.value} className="h-3 mb-3" />

              <div className="h-12 w-full">
                <ResponsiveContainer width="100%" height={48}>
                  <LineChart data={sparklineChartData}>
                    <Line
                      type="monotone"
                      dataKey="value"
                      stroke={`url(#gradient-${metric.id})`}
                      strokeWidth={2}
                      dot={false}
                    />
                    <defs>
                      <linearGradient id={`gradient-${metric.id}`} x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#3b82f6" />
                        <stop offset="100%" stopColor="#8b5cf6" />
                      </linearGradient>
                    </defs>
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          );
        })}
      </div>

      <div className="p-5 bg-gradient-to-r from-green-50 to-emerald-50 border-2 border-green-200 rounded-xl">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-green-600 rounded-lg">
            <Gauge className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="font-semibold text-green-900 mb-1">System Status</p>
            <p className="text-sm text-green-800">
              {overallScore > 80
                ? "Your system is running optimally with minimal security impact."
                : "System resources are under moderate load."}
            </p>
          </div>
        </div>
      </div>
    </Card>
  );
}