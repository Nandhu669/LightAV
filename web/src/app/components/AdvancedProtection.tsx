import { Shield, Globe, Download, FileWarning, Wifi, Eye, Lock, Mail } from "lucide-react";
import { Card } from "@/app/components/ui/card";
import { Switch } from "@/app/components/ui/switch";
import { Label } from "@/app/components/ui/label";
import { Separator } from "@/app/components/ui/separator";
import { Badge } from "@/app/components/ui/badge";
import { useState, useEffect } from "react";

interface ProtectionFeature {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  enabled: boolean;
  premium?: boolean;
  status?: "excellent" | "good" | "fair";
}

interface AdvancedProtectionProps {
  protectionStatus: boolean;
  onToggleProtection: () => void;
}

export function AdvancedProtection({ protectionStatus, onToggleProtection }: AdvancedProtectionProps) {
  const [features, setFeatures] = useState<ProtectionFeature[]>([
    {
      id: "realtime",
      title: "Real-Time Protection",
      description: "Continuously monitors and blocks threats in real-time",
      icon: Shield,
      enabled: protectionStatus,
      status: "excellent",
    },
    {
      id: "web",
      title: "Web Protection",
      description: "Blocks malicious websites and phishing attempts",
      icon: Globe,
      enabled: true,
      status: "excellent",
    },
    {
      id: "download",
      title: "Download Protection",
      description: "Automatically scans all downloaded files",
      icon: Download,
      enabled: true,
      status: "good",
    },
    {
      id: "ransomware",
      title: "Ransomware Shield",
      description: "Advanced protection against ransomware attacks",
      icon: FileWarning,
      enabled: true,
      premium: true,
      status: "excellent",
    },
    {
      id: "network",
      title: "Network Protection",
      description: "Monitors network traffic for suspicious activity",
      icon: Wifi,
      enabled: true,
      status: "good",
    },
    {
      id: "privacy",
      title: "Privacy Guard (Coming Soon)",
      description: "Protects your personal data and prevents tracking",
      icon: Eye,
      enabled: false,
      premium: true,
    },
    {
      id: "firewall",
      title: "Firewall Control",
      description: "Advanced firewall with custom rules",
      icon: Lock,
      enabled: true,
      status: "excellent",
    },
    {
      id: "email",
      title: "Email Protection (Coming Soon)",
      description: "Detects threats in attachments and links",
      icon: Mail,
      enabled: false,
    },
  ]);

  useEffect(() => {
    setFeatures(prev => prev.map(f =>
      f.id === "realtime" ? { ...f, enabled: protectionStatus } : f
    ));
  }, [protectionStatus]);

  const toggleFeature = (id: string) => {
    if (id === "realtime") {
      onToggleProtection();
    } else {
      setFeatures(features.map(f =>
        f.id === id ? { ...f, enabled: !f.enabled } : f
      ));
    }
  };

  const statusColors = {
    excellent: "bg-green-500",
    good: "bg-blue-500",
    fair: "bg-amber-500",
  };

  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 mb-1">Advanced Protection</h2>
          <p className="text-gray-600">Customize your security settings</p>
        </div>
        <Badge className="bg-gradient-to-r from-blue-600 to-purple-600 text-white">
          {features.filter(f => f.enabled).length} Layers Active
        </Badge>
      </div>

      <div className="space-y-1">
        {features.map((feature, index) => {
          const Icon = feature.icon;
          return (
            <div key={feature.id}>
              <div className="flex items-center justify-between py-5 group">
                <div className="flex items-start gap-4 flex-1">
                  <div className={`p-3 rounded-xl transition-all ${feature.enabled
                    ? 'bg-gradient-to-br from-blue-500 to-purple-600 shadow-lg shadow-blue-500/30'
                    : 'bg-gray-100'
                    }`}>
                    <Icon className={`w-6 h-6 ${feature.enabled ? 'text-white' : 'text-gray-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Label
                        htmlFor={feature.id}
                        className="text-base font-semibold text-gray-900 cursor-pointer"
                      >
                        {feature.title}
                      </Label>
                      {feature.premium && (
                        <Badge variant="outline" className="text-xs border-purple-300 text-purple-700">
                          Premium
                        </Badge>
                      )}
                      {feature.status && feature.enabled && (
                        <div className="flex items-center gap-1.5">
                          <div className={`w-2 h-2 rounded-full ${statusColors[feature.status]} animate-pulse`}></div>
                          <span className="text-xs text-gray-600 capitalize">{feature.status}</span>
                        </div>
                      )}
                    </div>
                    <p className="text-sm text-gray-600">{feature.description}</p>
                  </div>
                </div>
                <Switch
                  id={feature.id}
                  checked={feature.enabled}
                  onCheckedChange={() => toggleFeature(feature.id)}
                  className="ml-4"
                />
              </div>
              {index < features.length - 1 && <Separator />}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

