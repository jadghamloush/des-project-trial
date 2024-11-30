// src/utils/conversions.js

/**
 * Convert hexadecimal string to binary string.
 * @param {string} hex - Hexadecimal string.
 * @returns {string} Binary string.
 */
export const hexToBin = (hex) => {
    return hex
      .split('')
      .map((c) => parseInt(c, 16).toString(2).padStart(4, '0'))
      .join('');
  };
  
  /**
   * Convert hexadecimal string to byte array.
   * @param {string} hex - Hexadecimal string.
   * @returns {Uint8Array} Byte array.
   */
  export const hexToBytes = (hex) => {
    let bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  };
  