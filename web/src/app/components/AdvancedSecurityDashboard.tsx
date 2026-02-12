import { Shield, CheckCircle2, AlertTriangle, Clock, TrendingUp, Lock, ShieldOff } from "lucide-react";
import { Card } from "@/app/components/ui/card";
import { Badge } from "@/app/components/ui/badge";
import { Progress } from "@/app/components/ui/progress";
import { motion } from "motion/react";

interface AdvancedSecurityDashboardProps {
  protectionStatus: boolean;
  systemStats: {
    cpu: number;
    ram: number;
  };
}

export function AdvancedSecurityDashboard({ protectionStatus, systemStats }: AdvancedSecurityDashboardProps) {
  const protectionLevel = protectionStatus ? 100 : 0;
  const bgGradient = protectionStatus
    ? "from-green-600 to-emerald-600"
    : "from-orange-600 to-red-600";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Main Protection Status - Large Card */}
      <motion.div
        className="lg:col-span-5"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <Card className={`p-8 bg-gradient-to-br ${bgGradient} text-white border-0 shadow-xl relative overflow-hidden`}>
          <div className="absolute top-0 right-0 w-64 h-64 bg-white opacity-5 rounded-full -mr-32 -mt-32"></div>
          <div className="absolute bottom-0 left-0 w-48 h-48 bg-white opacity-5 rounded-full -ml-24 -mb-24"></div>

          <div className="relative z-10">
            <div className="flex items-center justify-between mb-6">
              <div className="p-3 bg-white/20 rounded-xl backdrop-blur-sm">
                {protectionStatus ? (
                  <Shield className="w-8 h-8" />
                ) : (
                  <ShieldOff className="w-8 h-8" />
                )}
              </div>
              <Badge className={`backdrop-blur-sm border-0 text-white ${protectionStatus ? 'bg-white/20' : 'bg-white/30'
                }`}>
                {protectionStatus ? (
                  <>
                    <CheckCircle2 className="w-3 h-3 mr-1" />
                    Active
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3 h-3 mr-1" />
                    Paused
                  </>
                )}
              </Badge>
            </div>

            <h3 className="text-3xl font-bold mb-2">
              {protectionStatus ? "You're Protected" : "Protection Paused"}
            </h3>
            <p className={protectionStatus ? "text-green-100 mb-6" : "text-orange-100 mb-6"}>
              {protectionStatus
                ? "All security features are active and running"
                : "Enable protection to secure your system"}
            </p>

            <div className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className={protectionStatus ? "text-green-100" : "text-orange-100"}>
                  Protection Level
                </span>
                <span className="font-semibold">
                  {protectionStatus ? "Maximum" : "Disabled"}
                </span>
              </div>
              <Progress value={protectionLevel} className="h-2 bg-white/20" />
            </div>

            <div className="grid grid-cols-2 gap-4 mt-6 pt-6 border-t border-white/20">
              <div>
                <p className={protectionStatus ? "text-green-100 text-sm mb-1" : "text-orange-100 text-sm mb-1"}>
                  CPU Usage
                </p>
                <p className="font-semibold">{systemStats.cpu.toFixed(1)}%</p>
              </div>
              <div>
                <p className={protectionStatus ? "text-green-100 text-sm mb-1" : "text-orange-100 text-sm mb-1"}>
                  RAM Usage
                </p>
                <p className="font-semibold">{systemStats.ram.toFixed(1)}%</p>
              </div>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Stats Grid */}
      <div className="lg:col-span-7 grid grid-cols-1 md:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
        >
          <Card className="p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 bg-blue-100 rounded-lg">
                <Clock className="w-6 h-6 text-blue-600" />
              </div>
              <Badge variant="outline" className="border-blue-300 text-blue-700">
                Real-time
              </Badge>
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Active Monitoring</h4>
            <p className="text-2xl font-bold text-blue-600 mb-1">
              {protectionStatus ? "24/7" : "Inactive"}
            </p>
            <p className="text-sm text-gray-600">
              {protectionStatus ? "Continuous protection enabled" : "Start protection to enable"}
            </p>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
        >
          <Card className="p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 bg-purple-100 rounded-lg">
                <Lock className="w-6 h-6 text-purple-600" />
              </div>
              <Badge variant="outline" className="border-purple-300 text-purple-700">
                {protectionStatus ? "Secure" : "Disabled"}
              </Badge>
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">System Protection</h4>
            <p className="text-2xl font-bold text-purple-600 mb-1">
              {protectionStatus ? "Protected" : "Paused"}
            </p>
            <p className="text-sm text-gray-600">
              {protectionStatus ? "File monitoring active" : "Protection is paused"}
            </p>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
        >
          <Card className="p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 bg-amber-100 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-amber-600" />
              </div>
              <Badge variant="outline" className="border-amber-300 text-amber-700">
                Monitored
              </Badge>
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Quarantined Items</h4>
            <p className="text-2xl font-bold text-amber-600 mb-1">-</p>
            <p className="text-sm text-gray-600">Threats isolated safely</p>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
        >
          <Card className="p-6 hover:shadow-lg transition-shadow">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 bg-green-100 rounded-lg">
                <TrendingUp className="w-6 h-6 text-green-600" />
              </div>
              <Badge variant="outline" className="border-green-300 text-green-700">
                Updated
              </Badge>
            </div>
            <h4 className="font-semibold text-gray-900 mb-1">Database Version</h4>
            <p className="text-2xl font-bold text-green-600 mb-1">Latest</p>
            <p className="text-sm text-gray-600">Signatures up to date</p>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
