"""
LightAV Entropy Module (Phase 4)

Shannon entropy calculation for raw bytes.
Used to measure randomness/compression of PE sections.

High entropy (>7.0) often indicates:
    - Packed/compressed executables
    - Encrypted content
    - Potential malware obfuscation

No external dependencies beyond standard library.
"""

import math
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of byte data.
    
    Shannon entropy formula:
        H = -sum(p(x) * log2(p(x))) for all byte values x
    
    Args:
        data: bytes or bytearray to analyze
        
    Returns:
        float: Entropy value between 0.0 and 8.0
               0.0 = completely uniform (all same byte)
               8.0 = maximum randomness (uniform distribution)
    
    Validation:
        - Empty data returns 0.0
        - Single repeated byte returns 0.0
        - Random data approaches 8.0
    """
    if not data:
        return 0.0
    
    length = len(data)
    if length == 0:
        return 0.0
    
    # Count byte occurrences
    byte_counts = Counter(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy
