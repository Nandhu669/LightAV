"""
Enhanced Heuristic Engine
Comprehensive static analysis with 20+ detection rules
"""

import numpy as np
import pefile
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from pathlib import Path


@dataclass
class HeuristicResult:
    """Result from heuristic analysis."""
    score: int                    # 0-100
    triggers: List[Dict]          # List of triggered rules
    confidence: float            # 0.0-1.0
    features: np.ndarray         # Extracted feature vector


class EnhancedHeuristicEngine:
    """
    Production-grade heuristic engine with 20+ detection rules.
    
    Expands LightAV's original 2 rules to comprehensive static analysis.
    """
    
    def __init__(self):
        """Initialize heuristic engine with all rules."""
        self.rules = self._define_rules()
        self.max_score = sum(r['weight'] for r in self.rules.values())
    
    def _define_rules(self) -> Dict:
        """Define all 20+ heuristic rules with weights."""
        return {
            # Critical rules (high weight)
            'high_entropy_unsigned': {
                'check': self._check_high_entropy_unsigned,
                'weight': 40,
                'severity': 'critical',
                'description': 'High entropy (>7.5) without digital signature'
            },
            'known_packer': {
                'check': self._check_known_packer,
                'weight': 30,
                'severity': 'high',
                'description': 'Known packing/protection tool detected'
            },
            'suspicious_imports': {
                'check': self._check_suspicious_imports,
                'weight': 35,
                'severity': 'critical',
                'description': 'Suspicious API imports detected'
            },
            
            # High severity rules
            'abnormal_sections': {
                'check': self._check_abnormal_sections,
                'weight': 10,
                'severity': 'medium',
                'description': 'Abnormal PE section count or names'
            },
            'suspicious_entry_point': {
                'check': self._check_entry_point,
                'weight': 25,
                'severity': 'high',
                'description': 'Entry point in unusual location'
            },
            'tls_callbacks': {
                'check': self._check_tls_callbacks,
                'weight': 20,
                'severity': 'high',
                'description': 'TLS callbacks present (anti-debug)'
            },
            'no_debug_info': {
                'check': self._check_no_debug_info,
                'weight': 15,
                'severity': 'medium',
                'description': 'No debug information (stripped)'
            },
            
            # Medium severity rules
            'high_iat_entropy': {
                'check': self._check_iat_entropy,
                'weight': 15,
                'severity': 'medium',
                'description': 'High import address table entropy'
            },
            'rwx_sections': {
                'check': self._check_rwx_sections,
                'weight': 25,
                'severity': 'high',
                'description': 'Read-Write-Execute sections present'
            },
            'suspicious_strings': {
                'check': self._check_suspicious_strings,
                'weight': 15,
                'severity': 'medium',
                'description': 'Suspicious strings in file'
            },
            'resource_anomaly': {
                'check': self._check_resource_anomaly,
                'weight': 15,
                'severity': 'medium',
                'description': 'Unusual resource section'
            },
            'low_import_count': {
                'check': self._check_low_imports,
                'weight': 15,
                'severity': 'medium',
                'description': 'Suspiciously low import count'
            },
            
            # Low severity rules (indicators)
            'unusual_timestamp': {
                'check': self._check_timestamp,
                'weight': 10,
                'severity': 'low',
                'description': 'Unusual compilation timestamp'
            },
            'overlay_data': {
                'check': self._check_overlay,
                'weight': 10,
                'severity': 'low',
                'description': 'Overlay data appended to file'
            },
            'rich_header_anomaly': {
                'check': self._check_rich_header,
                'weight': 10,
                'severity': 'low',
                'description': 'Rich header anomalies'
            },
            'code_section_small': {
                'check': self._check_code_size,
                'weight': 10,
                'severity': 'low',
                'description': 'Code section unusually small'
            },
            'high_data_ratio': {
                'check': self._check_data_ratio,
                'weight': 10,
                'severity': 'low',
                'description': 'High data-to-code ratio'
            },
            'suspicious_section_names': {
                'check': self._check_section_names,
                'weight': 10,
                'severity': 'low',
                'description': 'Suspicious section names'
            },
            'eponly_header': {
                'check': self._check_eponly,
                'weight': 10,
                'severity': 'low',
                'description': 'Executable-only header flags'
            },
            ' import_hash_rare': {
                'check': self._check_imphash,
                'weight': 10,
                'severity': 'low',
                'description': 'Rare import hash (imphash)'
            }
        }
    
    def analyze(self, file_path: str, features: Optional[np.ndarray] = None) -> HeuristicResult:
        """
        Run all heuristic rules on file.
        
        Args:
            file_path: Path to PE file
            features: Pre-extracted feature vector (optional)
            
        Returns:
            HeuristicResult with score and triggers
        """
        score = 0
        triggers = []
        
        # Extract features if not provided
        if features is None:
            features = self._extract_features(file_path)
        
        try:
            pe = pefile.PE(file_path, fast_load=True)
            
            # Run all rules
            for rule_name, rule in self.rules.items():
                try:
                    if rule['check'](pe, features, file_path):
                        score += rule['weight']
                        triggers.append({
                            'rule': rule_name,
                            'description': rule['description'],
                            'weight': rule['weight'],
                            'severity': rule['severity']
                        })
                except Exception as e:
                    # Individual rule failure shouldn't stop analysis
                    continue
            
            pe.close()
        except Exception as e:
            # If we can't parse the PE, give it a medium score
            score = 30
            triggers.append({
                'rule': 'pe_parse_error',
                'description': f'Could not parse PE file: {str(e)[:50]}',
                'weight': 30,
                'severity': 'medium'
            })
        
        # Normalize to 0-100
        normalized_score = min(int((score / self.max_score) * 100), 100)
        
        # Calculate confidence based on realistic max possible normalized score
        if normalized_score > 45:
            confidence = 0.9
        elif normalized_score > 25:
            confidence = 0.7
        elif normalized_score > 15:
            confidence = 0.5
        else:
            confidence = 0.2
        
        return HeuristicResult(
            score=normalized_score,
            triggers=triggers,
            confidence=confidence,
            features=features
        )
    
    # === Individual Rule Implementations ===
    
    def _check_high_entropy_unsigned(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """High entropy without signature."""
        # Features: 3=max_entropy, 6=has_signature
        max_entropy = features[3]
        has_signature = features[6]
        return max_entropy > 7.5 and has_signature == 0
    
    def _check_known_packer(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for known packers by section names."""
        packer_sections = [b'UPX', b'ASPack', b'Petite', b'Themida', b'VMProtect', 
                          b'PECompact', b'FSG', b'MPRESS', b'ExeStealth']
        
        for section in pe.sections:
            section_name = section.Name.rstrip(b'\x00')
            for packer in packer_sections:
                if packer in section_name:
                    return True
        return False
    
    def _check_suspicious_imports(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for suspicious API imports."""
        suspicious_apis = {
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtUnmapViewOfSection', 'SetWindowsHookEx', 'GetAsyncKeyState',
            'InternetOpenA', 'InternetConnectA', 'HttpSendRequestA',
            'CreateProcessA', 'WinExec', 'ShellExecuteA'
        }
        
        suspicious_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if hasattr(entry, 'imports'):
                    for imp in entry.imports:
                        if imp.name and imp.name.decode('utf-8', errors='ignore') in suspicious_apis:
                            suspicious_count += 1
        
        return suspicious_count >= 3
    
    def _check_abnormal_sections(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for abnormal section count."""
        section_count = len(pe.sections)
        return section_count < 2 or section_count > 12
    
    def _check_entry_point(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check if entry point is in unusual section."""
        if not hasattr(pe, 'OPTIONAL_HEADER'):
            return False
        
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Check if EP is in a non-standard section
        for section in pe.sections:
            start = section.VirtualAddress
            end = start + section.Misc_VirtualSize
            if start <= ep < end:
                section_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
                # Entry point should usually be in .text or CODE
                if section_name not in ['.text', '.code', 'CODE', 'text']:
                    return True
        return False
    
    def _check_tls_callbacks(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for TLS callbacks (often used for anti-debug)."""
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                return True
        except:
            pass
        return False
    
    def _check_no_debug_info(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check if debug information is stripped."""
        # Most malware strips debug info
        if hasattr(pe, 'OPTIONAL_HEADER'):
            debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]  # IMAGE_DIRECTORY_ENTRY_DEBUG
            return debug_dir.VirtualAddress == 0 or debug_dir.Size == 0
        return False
    
    def _check_iat_entropy(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for high entropy in import table."""
        # Calculate entropy of import names
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return False
        
        import_data = b''
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if hasattr(entry, 'imports'):
                for imp in entry.imports:
                    if imp.name:
                        import_data += imp.name
        
        if len(import_data) > 0:
            entropy = self._calculate_entropy(import_data)
            return entropy > 6.5
        return False
    
    def _check_rwx_sections(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for Read-Write-Execute sections."""
        for section in pe.sections:
            # Check if section has RWX permissions
            if (section.Characteristics & 0x20000000 and  # IMAGE_SCN_MEM_EXECUTE
                section.Characteristics & 0x40000000 and  # IMAGE_SCN_MEM_READ
                section.Characteristics & 0x80000000):    # IMAGE_SCN_MEM_WRITE
                return True
        return False
    
    def _check_suspicious_strings(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for suspicious strings in file."""
        suspicious_strings = [
            b'cmd.exe /c', b'powershell.exe', b'reg add',
            b'net user', b'CreateObject', b'WScript.Shell',
            b'eval(', b'base64', b'cmd /c'
        ]
        
        count = 0
        with open(file_path, 'rb') as f:
            data = f.read(65536)  # Read first 64KB
            for s in suspicious_strings:
                if s in data:
                    count += 1
        
        return count >= 2
    
    def _check_resource_anomaly(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for unusual resource section."""
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                # Check if resource section is too large (>50% of file)
                total_resource_size = 0
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    if hasattr(resource_lang, 'data'):
                                        total_resource_size += resource_lang.data.struct.Size
                
                file_size = Path(file_path).stat().st_size
                if file_size > 0:
                    return (total_resource_size / file_size) > 0.5
        except:
            pass
        return False
    
    def _check_low_imports(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for suspiciously low import count."""
        # Features: 5=num_imported_apis
        api_count = features[5]
        # Very few imports might indicate packed malware
        return api_count < 10 and api_count > 0
    
    def _check_timestamp(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for unusual compilation timestamp."""
        if hasattr(pe, 'FILE_HEADER'):
            timestamp = pe.FILE_HEADER.TimeDateStamp
            # Check if timestamp is in the future or too old
            import time
            current_time = int(time.time())
            # If timestamp is more than 5 years old or in future
            return timestamp > current_time or (current_time - timestamp) > (5 * 365 * 24 * 3600)
        return False
    
    def _check_overlay(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for overlay data."""
        # Overlay = data appended after PE sections
        last_section_end = 0
        for section in pe.sections:
            section_end = section.PointerToRawData + section.SizeOfRawData
            if section_end > last_section_end:
                last_section_end = section_end
        
        file_size = Path(file_path).stat().st_size
        return file_size > last_section_end + 100  # More than 100 bytes overlay
    
    def _check_rich_header(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for Rich header anomalies."""
        # Rich header is present in most legitimate PE files
        # Its absence or corruption can indicate tampering
        try:
            # Check if Rich header exists by looking for 'Rich' marker
            with open(file_path, 'rb') as f:
                data = f.read(1024)
                return b'Rich' not in data
        except:
            return True
    
    def _check_code_size(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check if code section is suspiciously small."""
        # Features: 8=size_of_code
        code_size = features[8]
        file_size = features[0] * 1024  # Convert KB to bytes
        
        if file_size > 0:
            return (code_size / file_size) < 0.1  # Less than 10% code
        return False
    
    def _check_data_ratio(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for high data-to-code ratio."""
        code_size = features[8]
        data_size = features[9]
        
        if code_size > 0:
            return (data_size / code_size) > 5  # More than 5x data vs code
        return False
    
    def _check_section_names(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for suspicious section names."""
        suspicious_names = [b'UPX', b'aspack', b'petite', b'.vmp', b'.themida',
                           b'pec', b'PEC2', b'pecompact', b'fsg']
        
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').lower()
            for suspicious in suspicious_names:
                if suspicious.lower() in name:
                    return True
        return False
    
    def _check_eponly(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for executable-only characteristics."""
        if hasattr(pe, 'FILE_HEADER'):
            # Check if relocation table is stripped (common in malware)
            return pe.FILE_HEADER.Characteristics & 0x0001  # IMAGE_FILE_RELOCS_STRIPPED
        return False
    
    def _check_imphash(self, pe: pefile.PE, features: np.ndarray, file_path: str) -> bool:
        """Check for rare import hash."""
        # imphash is a hash of the import table
        # Rare hashes can indicate unique/packed malware
        try:
            if hasattr(pe, 'get_imphash'):
                imphash = pe.get_imphash()
                # In production, you'd check against a database of known imphashes
                # For now, just check if it's valid
                return len(imphash) == 32 and imphash != '00000000000000000000000000000000'
        except:
            pass
        return False
    
    def _extract_features(self, file_path: str) -> np.ndarray:
        """Extract basic features for analysis."""
        from ai.feature_extractor import extract_features
        return extract_features(file_path)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
    
    def get_rule_list(self) -> List[Dict]:
        """Return list of all rules with descriptions."""
        return [
            {
                'name': name,
                'description': rule['description'],
                'weight': rule['weight'],
                'severity': rule['severity']
            }
            for name, rule in self.rules.items()
        ]


if __name__ == "__main__":
    # Test the heuristic engine
    print("=" * 60)
    print("Enhanced Heuristic Engine Test")
    print("=" * 60)
    print()
    
    engine = EnhancedHeuristicEngine()
    
    print(f"Total rules: {len(engine.rules)}")
    print(f"Max possible score: {engine.max_score}")
    print()
    
    # Test on a file if available
    test_files = [
        r"C:\Windows\System32\notepad.exe",
        "tests/samples/eicar.com"
    ]
    
    for test_file in test_files:
        if Path(test_file).exists():
            print(f"Testing: {test_file}")
            result = engine.analyze(test_file)
            print(f"  Score: {result.score}/100")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Triggers: {len(result.triggers)}")
            for trigger in result.triggers[:3]:  # Show first 3
                print(f"    - {trigger['rule']}: {trigger['description']}")
            print()
    
    print("Engine ready!")
