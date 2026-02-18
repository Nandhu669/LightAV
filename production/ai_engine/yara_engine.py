"""
YARA Engine Module
Pattern matching engine for malware detection
"""

import yara
import os
import requests
import zipfile
from pathlib import Path
from typing import List, Dict, Optional


class YARAEngine:
    """
    Production YARA engine for pattern-based malware detection.
    
    Features:
    - Compiles multiple YARA rule files
    - Rule categorization and weighting
    - Performance statistics
    - Easy rule management
    """
    
    def __init__(self, rules_dir: str = "production/ai_engine/yara_rules"):
        """
        Initialize YARA engine.
        
        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        self.rules = None
        self.rule_files = []
        self.rule_stats = {}
        
        # Load rules
        self._load_rules()
    
    def _load_rules(self):
        """Compile all YARA rules from directory."""
        rule_files = {}
        
        # Find all .yar and .yara files
        for ext in ['*.yar', '*.yara']:
            for rule_file in self.rules_dir.glob(ext):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
                self.rule_files.append(str(rule_file))
        
        if not rule_files:
            print("[YARA] Warning: No YARA rules found. Creating default rules...")
            self._create_default_rules()
            # Try loading again
            for ext in ['*.yar', '*.yara']:
                for rule_file in self.rules_dir.glob(ext):
                    namespace = rule_file.stem
                    rule_files[namespace] = str(rule_file)
                    self.rule_files.append(str(rule_file))
        
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"[YARA] Loaded {len(rule_files)} rule files")
            except yara.Error as e:
                print(f"[YARA] Error compiling rules: {e}")
                self.rules = None
        else:
            print("[YARA] Error: No rules could be loaded")
            self.rules = None
    
    def _create_default_rules(self):
        """Create default YARA rules for common malware patterns."""
        
        # Rule 1: High entropy detection
        high_entropy_rule = '''
rule HighEntropy_Executable {
    meta:
        description = "Detects executables with suspiciously high entropy"
        severity = "high"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and
        math.entropy(0, filesize) > 7.5
}
'''
        
        # Rule 2: Suspicious imports
        suspicious_imports_rule = '''
rule Suspicious_API_Imports {
    meta:
        description = "Detects suspicious Windows API imports"
        severity = "medium"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
        $api5 = "SetWindowsHookEx"
        $api6 = "GetAsyncKeyState"
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
'''
        
        # Rule 3: Common packers
        packer_rule = '''
rule Common_Packers {
    meta:
        description = "Detects common packers and protectors"
        severity = "low"
    strings:
        $upx = "UPX0"
        $upx1 = "UPX1"
        $aspack = "ASPack"
        $petite = "Petite"
        $themida = "Themida"
        $vmprotect = "VMProtect"
    condition:
        uint16(0) == 0x5A4D and
        any of them
}
'''
        
        # Rule 4: Suspicious strings
        suspicious_strings_rule = '''
rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings in executables"
        severity = "medium"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "reg add" nocase
        $s4 = "net user" nocase
        $s5 = "CreateObject" nocase
        $s6 = "WScript.Shell" nocase
        $s7 = "eval(" nocase
        $s8 = "base64" nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}
'''
        
        # Rule 5: Persistence mechanisms
        persistence_rule = '''
rule Persistence_Mechanisms {
    meta:
        description = "Detects common persistence mechanisms"
        severity = "high"
    strings:
        $run_key = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $startup = "\\\\Start Menu\\\\Programs\\\\Startup"
        $tasksched = "schtasks" nocase
        $wmi = "\\\\\\\\.\\root\\subscription"
    condition:
        uint16(0) == 0x5A4D and
        any of them
}
'''
        
        # Rule 6: Network indicators
        network_rule = '''
rule Network_Indicators {
    meta:
        description = "Detects network-related suspicious activity"
        severity = "medium"
    strings:
        $url1 = /https?:\\/\\/[a-z0-9]{20,50}/
        $ip = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/
        $socket = "WSASocket" nocase
        $connect = "WSAConnect" nocase
        $download = "URLDownloadToFile" nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
'''
        
        # Rule 7: Anti-analysis
        anti_analysis_rule = '''
rule Anti_Analysis {
    meta:
        description = "Detects anti-analysis techniques"
        severity = "high"
    strings:
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "CheckRemoteDebuggerPresent"
        $dbg3 = "NtGlobalFlag"
        $vm1 = "vmware"
        $vm2 = "virtualbox"
        $vm3 = "xen"
        $proc1 = "wireshark.exe" nocase
        $proc2 = "ollydbg.exe" nocase
        $proc3 = "processhacker.exe" nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($dbg*) or any of ($vm*) or 2 of ($proc*))
}
'''
        
        # Write default rules
        default_rules = [
            ("high_entropy", high_entropy_rule),
            ("suspicious_imports", suspicious_imports_rule),
            ("common_packers", packer_rule),
            ("suspicious_strings", suspicious_strings_rule),
            ("persistence", persistence_rule),
            ("network", network_rule),
            ("anti_analysis", anti_analysis_rule)
        ]
        
        for name, rule_content in default_rules:
            rule_file = self.rules_dir / f"{name}.yar"
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            print(f"[YARA] Created default rule: {name}.yar")
    
    def scan(self, file_path: str) -> List[yara.Match]:
        """
        Scan file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of YARA match objects
        """
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(file_path)
            
            # Update statistics
            for match in matches:
                rule_name = match.rule
                self.rule_stats[rule_name] = self.rule_stats.get(rule_name, 0) + 1
            
            return matches
        except yara.Error as e:
            print(f"[YARA] Error scanning {file_path}: {e}")
            return []
    
    def get_confidence(self, matches: List[yara.Match]) -> float:
        """
        Calculate confidence score from YARA matches.
        
        Args:
            matches: List of YARA matches
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not matches:
            return 0.0
        
        # Weight by severity
        severity_weights = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }
        
        total_weight = 0.0
        for match in matches:
            # Try to get severity from meta
            severity = 'low'  # default
            if hasattr(match, 'meta') and 'severity' in match.meta:
                severity = match.meta['severity']
            
            weight = severity_weights.get(severity, 0.5)
            total_weight += weight
        
        # Cap at 1.0
        return min(total_weight, 1.0)
    
    def get_match_details(self, matches: List[yara.Match]) -> List[Dict]:
        """
        Get detailed information about matches.
        
        Args:
            matches: List of YARA matches
            
        Returns:
            List of dictionaries with match details
        """
        details = []
        for match in matches:
            detail = {
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': list(match.tags) if hasattr(match, 'tags') else [],
                'meta': dict(match.meta) if hasattr(match, 'meta') else {},
                'strings': []
            }
            
            # Get matched strings
            if hasattr(match, 'strings'):
                for string_match in match.strings:
                    detail['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
            
            details.append(detail)
        
        return details
    
    def get_stats(self) -> Dict:
        """Return YARA engine statistics."""
        return {
            'rules_loaded': len(self.rule_files),
            'rule_files': self.rule_files,
            'match_stats': self.rule_stats,
            'total_matches': sum(self.rule_stats.values())
        }
    
    def reload_rules(self):
        """Reload all YARA rules."""
        self.rule_stats = {}
        self._load_rules()
    
    def add_rule_file(self, file_path: str) -> bool:
        """
        Add a new YARA rule file.
        
        Args:
            file_path: Path to YARA rule file
            
        Returns:
            True if added successfully
        """
        try:
            # Validate rule file
            yara.compile(filepath=file_path)
            
            # Copy to rules directory
            dest = self.rules_dir / Path(file_path).name
            import shutil
            shutil.copy(file_path, dest)
            
            # Reload rules
            self.reload_rules()
            return True
        except yara.Error as e:
            print(f"[YARA] Error adding rule file: {e}")
            return False


def download_yara_rules():
    """
    Download additional YARA rules from public repositories.
    Note: This requires internet access.
    """
    print("[YARA] Downloading additional YARA rules...")
    
    rules_dir = Path("production/ai_engine/yara_rules")
    rules_dir.mkdir(parents=True, exist_ok=True)
    
    # Sources to download from
    sources = {
        'yara-rules': 'https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip'
    }
    
    for name, url in sources.items():
        try:
            print(f"[YARA] Downloading from {name}...")
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            # Save zip
            zip_path = rules_dir / f"{name}.zip"
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(rules_dir / name)
            
            # Clean up zip
            zip_path.unlink()
            
            print(f"[YARA] Downloaded and extracted {name}")
            
        except Exception as e:
            print(f"[YARA] Error downloading {name}: {e}")
    
    print("[YARA] Download complete. Run YARAEngine.reload_rules() to load new rules.")


if __name__ == "__main__":
    # Test YARA engine
    print("=" * 60)
    print("YARA Engine Test")
    print("=" * 60)
    print()
    
    engine = YARAEngine()
    
    print(f"Loaded {len(engine.rule_files)} rule files:")
    for rule_file in engine.rule_files:
        print(f"  - {rule_file}")
    print()
    
    # Test on a sample file if available
    test_files = [
        "tests/samples/eicar.com",
        r"C:\Windows\System32\notepad.exe"
    ]
    
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Testing on: {test_file}")
            matches = engine.scan(test_file)
            if matches:
                print(f"  Matches: {len(matches)}")
                for match in matches:
                    print(f"    - {match.rule}")
            else:
                print("  No matches")
            print()
    
    print("Stats:", engine.get_stats())
