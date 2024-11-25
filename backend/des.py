# backend/des.py

from .key_expansion import generate_keys
from .utils import permute, shift_left, xor

# Initial Permutation (IP) Table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) Table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion (E) Table
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation Function (P) Table
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# S-boxes (S1 to S8)
S_BOX = [
    # S1
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    # S2
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    # S3
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    # S4
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    # S5
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    # S6
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    # S7
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    # S8
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]
]

def initial_permutation(block):
    """
    Apply the Initial Permutation (IP) to the input block.

    Args:
        block (list): A list of 64 bits.

    Returns:
        list: Permuted list of 64 bits.
    """
    return permute(block, IP)

def final_permutation(block):
    """
    Apply the Final Permutation (FP) to the input block.

    Args:
        block (list): A list of 64 bits.

    Returns:
        list: Permuted list of 64 bits.
    """
    return permute(block, FP)

def feistel(right, subkey):
    """
    The Feistel (F) function.

    Args:
        right (list): A list of 32 bits (R).
        subkey (list): A list of 48 bits (subkey).

    Returns:
        dict: A dictionary containing the outputs of each step.
    """
    # Expansion (E) - Expand 32 bits to 48 bits
    expanded_right = permute(right, E)
    # XOR with the subkey
    xor_result = xor(expanded_right, subkey)
    # S-box substitution
    sbox_output, sbox_details = s_box_substitution(xor_result)
    # Permutation (P)
    p_result = permute(sbox_output, P)
    return {
        'expanded_right': expanded_right.copy(),
        'xor_with_subkey': xor_result.copy(),
        'sbox_output': sbox_output.copy(),
        'sbox_details': sbox_details.copy(),
        'permutation_output': p_result.copy()
    }


def s_box_substitution(x):
    """
    Apply S-box substitution on the 48-bit input.

    Args:
        x (list): A list of 48 bits.

    Returns:
        list: A list of 32 bits after S-box substitution.
    """
    output = []
    sbox_details = []
    for i in range(8):
        # Extract 6 bits for the current S-box
        block = x[i*6:(i+1)*6]
        # Determine the row (first and last bits)
        row = (block[0] << 1) + block[5]
        # Determine the column (middle 4 bits)
        column = (block[1] << 3) + (block[2] << 2) + (block[3] << 1) + block[4]
        # Get the S-box value
        sbox_val = S_BOX[i][row][column]
        # Convert to 4-bit binary
        bin_val = [int(bit) for bit in bin(sbox_val)[2:].zfill(4)]
        output.extend(bin_val)
        sbox_details.append({
            'sbox': f'S{i+1}',
            'input': ''.join(str(bit) for bit in block),
            'row': row,
            'column': column,
            'output': ''.join(str(bit) for bit in bin_val)
        })
    return output, sbox_details

def des_encrypt(block, key):
    """
    Encrypt a 64-bit block using DES.

    Args:
        block (list): A list of 64 bits representing the plaintext.
        key (list): A list of 64 bits representing the key.

    Returns:
        tuple: (ciphertext as list of 64 bits, round details as list of dicts)
    """
    # Initial Permutation
    permuted_block = initial_permutation(block)
    left = permuted_block[:32]
    right = permuted_block[32:]

    # Key Schedule
    round_keys = generate_keys(key)

    round_details = []

    for i in range(16):
        round_number = i + 1
        feistel_output = feistel(right, round_keys[i])

        # Extract S-box details
        sbox_output, sbox_details = s_box_substitution(feistel_output['xor_with_subkey'])

        # Update feistel_output with S-box details
        feistel_output['sbox_output'] = sbox_output
        feistel_output['sbox_details'] = sbox_details

        # XOR with left
        new_right = xor(left, feistel_output['permutation_output'])

        # Collect round details
        round_info = {
            'round': round_number,
            'subkey': round_keys[i].copy(),
            'left_before': left.copy(),
            'right_before': right.copy(),
            'expanded_right': feistel_output['expanded_right'],
            'xor_with_subkey': feistel_output['xor_with_subkey'],
            'sbox_output': feistel_output['sbox_output'],
            'sbox_details': feistel_output['sbox_details'],
            'permutation_output': feistel_output['permutation_output'],
            'left_after': right.copy(),
            'right_after': new_right.copy()
        }
        round_details.append(round_info)

        # Update left and right for next round
        left = right
        right = new_right

    combined = right + left
    final_block = final_permutation(combined)
    return final_block, round_details



def des_decrypt(block, key):
    """
    Decrypt a 64-bit block using DES.

    Args:
        block (list): A list of 64 bits representing the ciphertext.
        key (list): A list of 64 bits representing the key.

    Returns:
        tuple: (plaintext as list of 64 bits, round details as list of dicts)
    """
    # Initial Permutation
    permuted_block = initial_permutation(block)
    left = permuted_block[:32]
    right = permuted_block[32:]

    # Key Schedule (reverse for decryption)
    round_keys = generate_keys(key)[::-1]

    round_details = []

    for i in range(16):
        round_number = i + 1
        feistel_output = feistel(right, round_keys[i])

        # Extract S-box details
        sbox_output, sbox_details = s_box_substitution(feistel_output['xor_with_subkey'])

        # Update feistel_output with S-box details
        feistel_output['sbox_output'] = sbox_output
        feistel_output['sbox_details'] = sbox_details

        # XOR with left
        new_right = xor(left, feistel_output['permutation_output'])

        # Collect round details
        round_info = {
            'round': round_number,
            'subkey': round_keys[i].copy(),
            'left_before': left.copy(),
            'right_before': right.copy(),
            'expanded_right': feistel_output['expanded_right'],
            'xor_with_subkey': feistel_output['xor_with_subkey'],
            'sbox_output': feistel_output['sbox_output'],
            'sbox_details': feistel_output['sbox_details'],
            'permutation_output': feistel_output['permutation_output'],
            'left_after': right.copy(),
            'right_after': new_right.copy()
        }
        round_details.append(round_info)

        # Update left and right for next round
        left = right
        right = new_right

    combined = right + left
    final_block = final_permutation(combined)
    return final_block, round_details
