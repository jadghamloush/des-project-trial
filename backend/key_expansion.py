# backend/key_expansion.py

from .utils import permute, shift_left

# Permuted Choice 1 (PC-1) Table
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2 (PC-2) Table
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Number of Left Shifts per Round
SHIFT_SCHEDULE = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
]

def generate_keys(key):
    """
    Generate 16 round keys from the original 64-bit key.

    Args:
        key (list): A list of 64 bits (integers 0 or 1).

    Returns:
        list: A list of 16 round keys, each a list of 48 bits.
    """
    # Apply Permuted Choice 1 (PC-1) to get 56-bit key
    key_permuted = permute(key, PC1)
    C = key_permuted[:28]
    D = key_permuted[28:]

    round_keys = []
    for shift in SHIFT_SCHEDULE:
        # Perform left shifts
        C = shift_left(C, shift)
        D = shift_left(D, shift)
        # Combine C and D
        combined = C + D
        # Apply Permuted Choice 2 (PC-2) to get the round key
        round_key = permute(combined, PC2)
        round_keys.append(round_key)
    return round_keys
