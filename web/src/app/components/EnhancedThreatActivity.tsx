import { Card } from "@/app/components/ui/card";
import { Badge } from "@/app/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/app/components/ui/tabs";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import { TrendingDown, Activity, Shield } from "lucide-react";

const threatsData = [
  { month: "Jan", blocked: 45, quarantined: 12, removed: 8 },
  { month: "Feb", blocked: 62, quarantined: 18, removed: 15 },
  { month: "Mar", blocked: 38, quarantined: 9, removed: 6 },
  { month: "Apr", blocked: 51, quarantined: 14, removed: 11 },
  { month: "May", blocked: 33, quarantined: 8, removed: 5 },
  { month: "Jun", blocked: 28, quarantined: 6, removed: 4 },
  { month: "Jul", blocked: 24, quarantined: 5, removed: 3 },
];

const weeklyData = [
  { day: "Mon", threats: 4 },
  { day: "Tue", threats: 7 },
  { day: "Wed", threats: 3 },
  { day: "Thu", threats: 8 },
  { day: "Fri", threats: 5 },
  { day: "Sat", threats: 2 },
  { day: "Sun", threats: 1 },
];

export function EnhancedThreatActivity() {
  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-1">Threat Analytics</h2>
          <p className="text-gray-600">Monitor security threats over time</p>
        </div>
        <Badge variant="outline" className="border-green-300 text-green-700">
          <TrendingDown className="w-3 h-3 mr-1" />
          -32% vs last month
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="mb-6">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Activity className="w-4 h-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="weekly" className="flex items-center gap-2">
            <Shield className="w-4 h-4" />
            This Week
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-0">
          {/* Stats Cards */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
              <p className="text-sm text-blue-700 font-medium mb-1">Total Blocked</p>
              <p className="text-2xl font-bold text-blue-900">281</p>
            </div>
            <div className="p-4 bg-amber-50 rounded-lg border border-amber-200">
              <p className="text-sm text-amber-700 font-medium mb-1">Quarantined</p>
              <p className="text-2xl font-bold text-amber-900">72</p>
            </div>
            <div className="p-4 bg-green-50 rounded-lg border border-green-200">
              <p className="text-sm text-green-700 font-medium mb-1">Removed</p>
              <p className="text-2xl font-bold text-green-900">52</p>
            </div>
          </div>

          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={threatsData}>
              <defs>
                <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1} />
                </linearGradient>
                <linearGradient id="colorQuarantined" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.1} />
                </linearGradient>
                <linearGradient id="colorRemoved" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.1} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="month" stroke="#6b7280" fontSize={12} />
              <YAxis stroke="#6b7280" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                }}
              />
              <Legend />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#3b82f6"
                fillOpacity={1}
                fill="url(#colorBlocked)"
                name="Blocked"
              />
              <Area
                type="monotone"
                dataKey="quarantined"
                stroke="#f59e0b"
                fillOpacity={1}
                fill="url(#colorQuarantined)"
                name="Quarantined"
              />
              <Area
                type="monotone"
                dataKey="removed"
                stroke="#10b981"
                fillOpacity={1}
                fill="url(#colorRemoved)"
                name="Removed"
              />
            </AreaChart>
          </ResponsiveContainer>
        </TabsContent>

        <TabsContent value="weekly" className="mt-0">
          <div className="w-full h-[300px]">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={weeklyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="day" stroke="#6b7280" fontSize={12} />
                <YAxis stroke="#6b7280" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                  cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}
                />
                <Bar
                  dataKey="threats"
                  fill="url(#barGradient)"
                  radius={[8, 8, 0, 0]}
                  name="Threats"
                />
                <defs>
                  <linearGradient id="barGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6366f1" />
                    <stop offset="100%" stopColor="#8b5cf6" />
                  </linearGradient>
                </defs>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </TabsContent>
      </Tabs>
    </Card>
  );
}