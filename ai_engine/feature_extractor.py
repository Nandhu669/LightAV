"""
LightAV Static Feature Extractor (Phase 4)

Converts PE files (.exe, .dll) into fixed-length numeric vectors
for machine learning classification.

Feature Vector (length 10, fixed order):
    Index 0: File size in KB
    Index 1: Number of sections
    Index 2: Mean section entropy
    Index 3: Maximum section entropy
    Index 4: Number of imported DLLs
    Index 5: Number of imported APIs
    Index 6: Has digital signature (0 or 1)
    Index 7: Entry point RVA
    Index 8: Size of code section
    Index 9: Size of initialized data section

Dependencies:
    - pefile: PE file parsing
    - numpy: Output array format

Validation:
    - Feature vector shape equals (10,)
    - Repeated extraction returns identical results
    - Same input always produces same output (deterministic)
"""

import os
import numpy as np
import pefile

from ai_engine.entropy import calculate_entropy


# Security Certificate directory index in PE
IMAGE_DIRECTORY_ENTRY_SECURITY = 4


def extract_features(file_path):
    """
    Extract static features from a PE file.
    
    Args:
        file_path: Path to the PE file (.exe or .dll)
        
    Returns:
        numpy.ndarray: Feature vector of shape (10,) with dtype float32
        
    Raises:
        FileNotFoundError: If file does not exist
        pefile.PEFormatError: If file is not a valid PE
        
    Validation:
        >>> features = extract_features("sample.exe")
        >>> features.shape
        (10,)
        >>> features.dtype
        float32
        >>> np.array_equal(extract_features("sample.exe"), features)
        True
    """
    # Initialize feature array
    features = np.zeros(10, dtype=np.float32)
    
    # Feature 0: File size in KB
    file_size_bytes = os.path.getsize(file_path)
    features[0] = file_size_bytes / 1024.0
    
    # Parse PE file
    pe = pefile.PE(file_path, fast_load=True)
    
    # Load required directories for imports and security
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
    ])
    
    # Feature 1: Number of sections
    features[1] = len(pe.sections)
    
    # Features 2, 3: Section entropies
    section_entropies = []
    for section in pe.sections:
        section_data = section.get_data()
        entropy = calculate_entropy(section_data)
        section_entropies.append(entropy)
    
    if section_entropies:
        features[2] = sum(section_entropies) / len(section_entropies)  # Mean
        features[3] = max(section_entropies)                           # Maximum
    else:
        features[2] = 0.0
        features[3] = 0.0
    
    # Features 4, 5: Import statistics
    num_dlls = 0
    num_apis = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            num_dlls += 1
            if hasattr(entry, 'imports'):
                num_apis += len(entry.imports)
    
    features[4] = num_dlls
    features[5] = num_apis
    
    # Feature 6: Has digital signature (0 or 1)
    has_signature = 0
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > IMAGE_DIRECTORY_ENTRY_SECURITY:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY]
            if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                has_signature = 1
    
    features[6] = has_signature
    
    # Feature 7: Entry point RVA
    if hasattr(pe, 'OPTIONAL_HEADER'):
        features[7] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    
    # Features 8, 9: Code and data section sizes
    if hasattr(pe, 'OPTIONAL_HEADER'):
        features[8] = pe.OPTIONAL_HEADER.SizeOfCode
        features[9] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    
    # Clean up
    pe.close()
    
    return features


def get_feature_names():
    """
    Return ordered list of feature names.
    
    Returns:
        list: Feature names matching vector indices
    """
    return [
        "file_size_kb",
        "num_sections",
        "mean_entropy",
        "max_entropy",
        "num_imported_dlls",
        "num_imported_apis",
        "has_signature",
        "entry_point_rva",
        "size_of_code",
        "size_of_initialized_data",
    ]
