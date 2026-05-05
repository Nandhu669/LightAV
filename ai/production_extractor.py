"""
Production PE Feature Extractor
Extracts 77 header and structural features for the LightGBM ONNX model.
Designed for high speed and minimal pipeline impact.

Supports two calling modes:
  extract_production_features(path)         – reads file from disk
  extract_production_features_from_bytes(raw_bytes)  – in-memory (no disk I/O)
"""

import os
import numpy as np
import pefile
from typing import Optional, Union


def _build_features(pe: pefile.PE) -> Optional[np.ndarray]:
    """
    Core feature extraction from an already-parsed pefile.PE object.
    Returns a 77-element float32 array, or None on critical error.
    """
    try:
        res = []

        # ── DOS Header (0-16) ────────────────────────────────────────────
        res.append(pe.DOS_HEADER.e_magic)
        res.append(pe.DOS_HEADER.e_cblp)
        res.append(pe.DOS_HEADER.e_cp)
        res.append(pe.DOS_HEADER.e_crlc)
        res.append(pe.DOS_HEADER.e_cparhdr)
        res.append(pe.DOS_HEADER.e_minalloc)
        res.append(pe.DOS_HEADER.e_maxalloc)
        res.append(pe.DOS_HEADER.e_ss)
        res.append(pe.DOS_HEADER.e_sp)
        res.append(pe.DOS_HEADER.e_csum)
        res.append(pe.DOS_HEADER.e_ip)
        res.append(pe.DOS_HEADER.e_cs)
        res.append(pe.DOS_HEADER.e_lfarlc)
        res.append(pe.DOS_HEADER.e_ovno)
        res.append(pe.DOS_HEADER.e_oemid)
        res.append(pe.DOS_HEADER.e_oeminfo)
        res.append(pe.DOS_HEADER.e_lfanew)

        # ── File Header (17-23) ──────────────────────────────────────────
        res.append(pe.FILE_HEADER.Machine)
        res.append(pe.FILE_HEADER.NumberOfSections)
        res.append(pe.FILE_HEADER.TimeDateStamp)
        res.append(pe.FILE_HEADER.PointerToSymbolTable)
        res.append(pe.FILE_HEADER.NumberOfSymbols)
        res.append(pe.FILE_HEADER.SizeOfOptionalHeader)
        res.append(pe.FILE_HEADER.Characteristics)

        # ── Optional Header (24-51) ──────────────────────────────────────
        oh = pe.OPTIONAL_HEADER
        res.append(oh.Magic)
        res.append(oh.MajorLinkerVersion)
        res.append(oh.MinorLinkerVersion)
        res.append(oh.SizeOfCode)
        res.append(oh.SizeOfInitializedData)
        res.append(oh.SizeOfUninitializedData)
        res.append(oh.AddressOfEntryPoint)
        res.append(oh.BaseOfCode)
        res.append(oh.ImageBase)
        res.append(oh.SectionAlignment)
        res.append(oh.FileAlignment)
        res.append(oh.MajorOperatingSystemVersion)
        res.append(oh.MinorOperatingSystemVersion)
        res.append(oh.MajorImageVersion)
        res.append(oh.MinorImageVersion)
        res.append(oh.MajorSubsystemVersion)
        res.append(oh.MinorSubsystemVersion)
        res.append(oh.SizeOfHeaders)
        res.append(oh.CheckSum)
        res.append(oh.SizeOfImage)
        res.append(oh.Subsystem)
        res.append(oh.DllCharacteristics)
        res.append(oh.SizeOfStackReserve)
        res.append(oh.SizeOfStackCommit)
        res.append(oh.SizeOfHeapReserve)
        res.append(oh.SizeOfHeapCommit)
        res.append(oh.LoaderFlags)
        res.append(oh.NumberOfRvaAndSizes)

        # Index 52: label column in training CSV — always 0 at inference
        res.append(0)

        # ── Structural Features (53-76) ──────────────────────────────────

        # 53: SuspiciousImportFunctions
        suspicious_apis = [
            'CreateProcess', 'InternetOpen', 'ShellExecute',
            'VirtualAlloc', 'GetProcAddress', 'WriteProcessMemory',
            'CreateRemoteThread', 'LoadLibrary'
        ]
        count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('utf-8', 'ignore')
                        if any(s in name for s in suspicious_apis):
                            count += 1
        res.append(count)

        # 54: SuspiciousNameSection
        std_names = ['.text', '.data', '.rdata', '.idata',
                     '.edata', '.rsrc', '.reloc', '.bss', '.tls']
        susp_sec = 0
        for sec in pe.sections:
            name = sec.Name.decode('utf-8', 'ignore').strip('\x00')
            if name not in std_names:
                susp_sec += 1
        res.append(susp_sec)

        # 55: SectionsLength
        res.append(len(pe.sections))

        # 56-57: Min / Max section entropy
        entropies = [s.get_entropy() for s in pe.sections]
        res.append(min(entropies) if entropies else 0)
        res.append(max(entropies) if entropies else 0)

        # 58-61: Raw / Virtual section sizes (min & max)
        raw_sizes  = [s.SizeOfRawData      for s in pe.sections]
        virt_sizes = [s.Misc_VirtualSize   for s in pe.sections]
        res.append(min(raw_sizes)  if raw_sizes  else 0)
        res.append(max(raw_sizes)  if raw_sizes  else 0)
        res.append(min(virt_sizes) if virt_sizes else 0)
        res.append(max(virt_sizes) if virt_sizes else 0)

        # 62-65: Repeated (max/min raw/virtual) — matches training CSV layout
        res.append(max(raw_sizes)  if raw_sizes  else 0)
        res.append(min(raw_sizes)  if raw_sizes  else 0)
        res.append(max(virt_sizes) if virt_sizes else 0)
        res.append(min(virt_sizes) if virt_sizes else 0)

        # 66-67: PointerToRawData (max / min)
        ptr_data = [s.PointerToRawData for s in pe.sections]
        res.append(max(ptr_data) if ptr_data else 0)
        res.append(min(ptr_data) if ptr_data else 0)

        # 68-69: Section characteristics
        chars = [s.Characteristics for s in pe.sections]
        res.append(max(chars)    if chars else 0)
        res.append(chars[0]      if chars else 0)

        # 70-71: Import directory (DLL count / total imports)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            res.append(len(pe.DIRECTORY_ENTRY_IMPORT))
            res.append(sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT))
        else:
            res.append(0)
            res.append(0)

        # 72: Export count
        res.append(
            len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        )

        # 73-76: Data directory sizes (Export, Import, Resource, Security)
        def get_dir_size(idx):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > idx:
                return pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].Size
            return 0

        res.append(get_dir_size(0))   # Export
        res.append(get_dir_size(1))   # Import
        res.append(get_dir_size(2))   # Resource
        res.append(get_dir_size(4))   # Security

        # ── Finalise ─────────────────────────────────────────────────────
        final = np.array(res, dtype=np.float32)

        if len(final) > 77:
            return final[:77]
        elif len(final) < 77:
            return np.pad(final, (0, 77 - len(final)))

        return final

    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API — path-based (original interface, unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def extract_production_features(file_path: str) -> Optional[np.ndarray]:
    """
    Extract 77 PE features from a file on disk.

    Args:
        file_path: Absolute or relative path to a PE file (.exe/.dll/etc.)

    Returns:
        float32 ndarray of shape (77,), or None if parsing failed.
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        result = _build_features(pe)
        pe.close()
        return result
    except Exception as e:
        # Silently return None — caller decides how to handle
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public API — in-memory (never touches disk)
# ─────────────────────────────────────────────────────────────────────────────

def extract_production_features_from_bytes(raw_bytes: bytes) -> Optional[np.ndarray]:
    """
    Extract 77 PE features from raw file bytes — NO disk I/O.

    This is the safe way to handle malware samples: the bytes are
    loaded entirely in RAM and pefile never needs a file path.
    Windows Defender cannot scan BytesIO objects.

    Args:
        raw_bytes: Raw bytes of a PE file (from zipfile, HTTP, etc.)

    Returns:
        float32 ndarray of shape (77,), or None if parsing failed.
    """
    try:
        pe = pefile.PE(data=raw_bytes, fast_load=True)
        result = _build_features(pe)
        pe.close()
        return result
    except Exception:
        return None
