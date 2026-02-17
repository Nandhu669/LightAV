import { Search, Zap, HardDrive, FileCheck, Folder, Globe, Shield } from "lucide-react";
import { Card } from "@/app/components/ui/card";
import { Button } from "@/app/components/ui/button";
import { motion } from "motion/react";
import { useState } from "react";

interface ScanOption {
  id: string;
  title: string;
  description: string;
  details: string;
  icon: React.ElementType;
  duration: string;
  color: string;
  bgColor: string;
  recommended?: boolean;
}

const scanOptions: ScanOption[] = [
  {
    id: "quick",
    title: "Quick Scan",
    description: "Fast scan of critical system areas",
    details: "Scans memory, startup items, and system files",
    icon: Zap,
    duration: "~2 min",
    color: "text-blue-600",
    bgColor: "bg-blue-50",
    recommended: true,
  },
  {
    id: "full",
    title: "Full System Scan",
    description: "Complete deep scan of all files",
    details: "Thorough scan of entire system including archives",
    icon: HardDrive,
    duration: "~45 min",
    color: "text-purple-600",
    bgColor: "bg-purple-50",
  },
  {
    id: "custom",
    title: "Custom Scan",
    description: "Select specific files and folders",
    details: "Choose what to scan with custom settings",
    icon: FileCheck,
    duration: "Varies",
    color: "text-green-600",
    bgColor: "bg-green-50",
  },
  {
    id: "vulnerability",
    title: "Vulnerability Scan",
    description: "Check for system weaknesses",
    details: "Identifies security vulnerabilities and updates",
    icon: Shield,
    duration: "~5 min",
    color: "text-red-600",
    bgColor: "bg-red-50",
  },
  {
    id: "external",
    title: "External Devices",
    description: "Scan USB drives and external media",
    details: "Protect against infected removable devices",
    icon: Folder,
    duration: "~3 min",
    color: "text-orange-600",
    bgColor: "bg-orange-50",
  },
  {
    id: "network",
    title: "Network Scan",
    description: "Scan network connections",
    details: "Monitor and secure network traffic",
    icon: Globe,
    duration: "~4 min",
    color: "text-cyan-600",
    bgColor: "bg-cyan-50",
  },
];

interface PremiumScanOptionsProps {
  onScan: (path: string) => void;
  onFolderScan: (path: string) => void;
  onFullScan: () => void;
  onNetworkScan: () => void;
  onVulnerabilityScan: () => void;
  pybridge?: any;
}

export function PremiumScanOptions({
  onScan,
  onFolderScan,
  onFullScan,
  onNetworkScan,
  onVulnerabilityScan,
  pybridge
}: PremiumScanOptionsProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const handleScan = (id: string) => {
    if (id === "quick") {
      if (pybridge) {
        pybridge.select_file((selectedPath: string) => {
          if (selectedPath) onScan(selectedPath);
        });
        return;
      }
      const path = prompt("Enter file path for Quick Scan:", "C:\\Windows\\System32\\drivers\\etc\\hosts") || "";
      if (path) onScan(path);
    } else if (id === "full") {
      onFullScan();
    } else if (id === "custom") {
      if (pybridge) {
        pybridge.select_folder((selectedPath: string) => {
          if (selectedPath) onFolderScan(selectedPath);
        });
        return;
      }
      const path = prompt("Enter folder path to scan:") || "";
      if (path) onFolderScan(path);
    } else if (id === "external") {
      if (pybridge) {
        pybridge.select_folder((selectedPath: string) => {
          if (selectedPath) onFolderScan(selectedPath);
        });
        return;
      }
      const path = prompt("Enter external drive path to scan:") || "";
      if (path) onFolderScan(path);
    } else if (id === "network") {
      onNetworkScan();
    } else if (id === "vulnerability") {
      onVulnerabilityScan();
    } else {
      alert("This scan type is not yet implemented in the backend.");
      return;
    }
  };

  return (
    <Card className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Search className="w-6 h-6 text-gray-700" />
            <h2 className="text-2xl font-bold text-gray-900">Scan Your System</h2>
          </div>
          <p className="text-gray-600">Choose a scan type to protect your device</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {scanOptions.map((option, index) => {
          const Icon = option.icon;
          const isHovered = hoveredId === option.id;

          return (
            <motion.div
              key={option.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              onMouseEnter={() => setHoveredId(option.id)}
              onMouseLeave={() => setHoveredId(null)}
            >
              <Card
                className={`p-6 cursor-pointer border-2 transition-all duration-300 relative overflow-hidden ${isHovered
                  ? 'shadow-xl scale-105 border-blue-400'
                  : 'hover:shadow-lg border-gray-200'
                  }`}
                onClick={() => handleScan(option.id)}
              >
                {option.recommended && (
                  <div className="absolute top-0 right-0">
                    <div className="bg-gradient-to-br from-blue-600 to-purple-600 text-white text-xs font-semibold px-3 py-1 rounded-bl-lg">
                      Recommended
                    </div>
                  </div>
                )}

                <div className={`p-4 rounded-xl ${option.bgColor} mb-4 inline-block`}>
                  <Icon className={`w-8 h-8 ${option.color}`} />
                </div>

                <h3 className="font-bold text-gray-900 mb-2 text-lg">{option.title}</h3>
                <p className="text-sm text-gray-700 mb-2">{option.description}</p>
                <p className="text-xs text-gray-500 mb-4">{option.details}</p>

                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs text-gray-600 font-medium">Duration: {option.duration}</span>
                </div>

                <Button
                  className={`w-full transition-all ${option.recommended
                    ? 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700'
                    : ''
                    }`}
                  variant={option.recommended ? "default" : "outline"}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleScan(option.id);
                  }}
                >
                  Start Scan
                </Button>
              </Card>
            </motion.div>
          );
        })}
      </div>
    </Card>
  );
}

