# backend/utils.py

def permute(block, table):
    """
    Permute the input block based on the provided table.

    Args:
        block (list): A list of bits.
        table (list): A list defining the permutation order.

    Returns:
        list: Permuted list of bits.

    Raises:
        ValueError: If the block size is smaller than the maximum index in the table.
    """
    if len(block) < max(table):
        raise ValueError(f"Block size {len(block)} is smaller than the maximum table index {max(table)}.")
    return [block[x - 1] for x in table]

def shift_left(block, n):
    """
    Perform left circular shift on the block.

    Args:
        block (list): A list of bits.
        n (int): Number of positions to shift.

    Returns:
        list: Shifted list of bits.
    """
    return block[n:] + block[:n]

def xor(a, b):
    """
    Perform bitwise XOR on two lists of bits.

    Args:
        a (list): First list of bits.
        b (list): Second list of bits.

    Returns:
        list: Resulting list after XOR.
    """
    return [x ^ y for x, y in zip(a, b)]

def hex_to_bin(hex_str):
    """
    Convert a hexadecimal string to a list of bits.

    Args:
        hex_str (str): Hexadecimal string.

    Returns:
        list: List of bits.
    """
    scale = 16  # Hexadecimal
    num_of_bits = len(hex_str) * 4
    bin_str = bin(int(hex_str, scale))[2:].zfill(num_of_bits)
    return [int(bit) for bit in bin_str]

def bin_to_hex(bin_list):
    """
    Convert a list of bits to a hexadecimal string.

    Args:
        bin_list (list): List of bits.

    Returns:
        str: Hexadecimal string.
    """
    bin_str = ''.join(str(bit) for bit in bin_list)
    hex_str = hex(int(bin_str, 2))[2:].upper()
    # Calculate the required padding (16 hex characters for 64 bits)
    padding_length = 16 - len(hex_str)
    if padding_length > 0:
        hex_str = '0' * padding_length + hex_str
    return hex_str

def ascii_to_hex(text):
    """
    Convert ASCII text to a hexadecimal string.

    Args:
        text (str): ASCII text.

    Returns:
        str: Hexadecimal representation of the text.
    """
    return text.encode('utf-8').hex().upper()

def is_valid_hex(hex_str):
    """
    Check if a string is a valid hexadecimal.

    Args:
        hex_str (str): String to validate.

    Returns:
        bool: True if valid hex, False otherwise.
    """
    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False

def is_valid_binary(bin_str):
    """
    Check if a string is a valid binary string.

    Args:
        bin_str (str): String to validate.

    Returns:
        bool: True if valid binary, False otherwise.
    """
    return all(bit in ['0', '1'] for bit in bin_str)
