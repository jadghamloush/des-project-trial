# backend/app.py

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .des import des_encrypt, des_decrypt
from .key_expansion import generate_keys
from .utils import hex_to_bin, bin_to_hex, ascii_to_hex, is_valid_hex, is_valid_binary
import time
import random
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import magic  # For MIME type detection
import logging
import base64  # Import base64 for encoding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configure rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Constants
ALLOWED_EXTENSIONS = {'txt'}

# Set maximum allowed payload to 1MB (adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

def allowed_file(file_stream, filename):
    """
    Check if the uploaded file has an allowed extension and MIME type.
    """
    if '.' in filename and \
       filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
        # Check MIME type using magic
        try:
            mime = magic.from_buffer(file_stream.read(1024), mime=True)
            file_stream.seek(0)  # Reset stream position
            return mime == 'text/plain'
        except Exception as e:
            logger.error(f"MIME type detection failed: {str(e)}")
            return False
    return False

def convert_input(data, input_format):
    """
    Convert input data based on the specified format to binary.

    Args:
        data (str): The input data as a string.
        input_format (str): The format of the input data ('hex', 'text', 'binary').

    Returns:
        list: A list of bits representing the binary data.

    Raises:
        ValueError: If the input data is invalid or not in the expected format.
    """
    if input_format == 'hex':
        if not is_valid_hex(data):
            raise ValueError("Invalid hexadecimal input.")
        return hex_to_bin(data)
    elif input_format == 'text':
        # Ensure text is ASCII
        try:
            data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError("Text contains non-ASCII characters.")
        hex_data = ascii_to_hex(data)
        return hex_to_bin(hex_data)
    elif input_format == 'binary':
        if not is_valid_binary(data):
            raise ValueError("Invalid binary input.")
        if len(data) != 64:
            raise ValueError("Binary input must be exactly 64 bits.")
        return [int(bit) for bit in data]
    else:
        raise ValueError("Unsupported input format.")

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'message': 'File is too large. Maximum allowed size is 1MB.'}), 413

@app.route('/encrypt', methods=['POST'])
@limiter.limit("10 per minute")  # Example: 10 requests per minute
def encrypt():
    """
    Encrypt a message using DES.

    Expects multipart/form-data with:
    - 'key': string (hexadecimal, 16 characters)
    - 'input_format': string ('hex', 'text', 'binary', 'file')
    - 'message': string or file, depending on 'input_format'

    Returns:
        JSON response with ciphertext, round details, time taken, and success status.
    """
    if 'input_format' not in request.form:
        return jsonify({'success': False, 'message': 'Input format is required.'}), 400

    input_format = request.form['input_format'].lower()

    # Retrieve and validate key
    key_hex = request.form.get('key', '').strip()
    if not key_hex or len(key_hex) != 16 or not is_valid_hex(key_hex):
        return jsonify({'success': False, 'message': 'Key must be exactly 16 hexadecimal characters.'}), 400

    try:
        key_bin = hex_to_bin(key_hex)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid hexadecimal key.'}), 400

    # Retrieve message based on input_format
    if input_format == 'file':
        if 'message' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
        file = request.files['message']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file.'}), 400
        if file and allowed_file(file.stream, file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            logger.info(f"File uploaded: {filename} from {request.remote_addr}")

            # Process the file (in-memory)
            try:
                content = file.read().decode('utf-8').strip()
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File contains invalid UTF-8 characters.'}), 400

            # Ensure content is valid ASCII
            try:
                content.encode('ascii')
            except UnicodeEncodeError:
                return jsonify({'success': False, 'message': 'File contains non-ASCII characters.'}), 400

            # Directly convert hex to binary without re-conversion
            try:
                message_bin = hex_to_bin(content)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Failed to convert hex to binary: {str(e)}'}), 400

        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Only .txt files are allowed.'}), 400
    else:
        message = request.form.get('message', '').strip()
        if not message:
            return jsonify({'success': False, 'message': 'Message is required.'}), 400
        try:
            message_bin = convert_input(message, input_format)
            ciphertext_hex = bin_to_hex(message_bin)
        except ValueError as ve:
            return jsonify({'success': False, 'message': str(ve)}), 400

    # Ensure message is 64 bits (16 hex characters)
    if len(message_bin) != 64:
        return jsonify({'success': False, 'message': 'Message must be exactly 64 bits (16 hexadecimal characters).' }), 400

    # Perform encryption
    try:
        start_time = time.time()
        ciphertext_bin, round_details = des_encrypt(message_bin, key_bin)
        end_time = time.time()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return jsonify({'success': False, 'message': f'Encryption failed: {str(e)}'}), 500

    ciphertext_hex = bin_to_hex(ciphertext_bin)
    elapsed_time = end_time - start_time

    # Prepare detailed round details for frontend
    detailed_rounds = []
    for round_info in round_details:
        detailed_rounds.append({
            'round': round_info['round'],
            'subkey': round_info['subkey'],
            'left_before': round_info['left_before'],
            'right_before': round_info['right_before'],
            'expanded_right': round_info['expanded_right'],
            'xor_with_subkey': round_info['xor_with_subkey'],
            'sbox_details': round_info['sbox_details'],
            'permutation_output': round_info['permutation_output'],
            'left_after': round_info['left_after'],
            'right_after': round_info['right_after']
        })

    response = {
        'success': True,
        'ciphertext': ciphertext_hex,
        'round_details': detailed_rounds,  # Updated to include detailed information
        'time_taken': elapsed_time
    }
    return jsonify(response), 200




@app.route('/decrypt', methods=['POST'])
@limiter.limit("10 per minute")  # Example: 10 requests per minute
def decrypt():
    if 'input_format' not in request.form:
        return jsonify({'success': False, 'message': 'Input format is required.'}), 400

    input_format = request.form['input_format'].lower()

    # Retrieve and validate key
    key_hex = request.form.get('key', '').strip()
    if not key_hex or len(key_hex) != 16 or not is_valid_hex(key_hex):
        return jsonify({'success': False, 'message': 'Key must be exactly 16 hexadecimal characters.'}), 400

    try:
        key_bin = hex_to_bin(key_hex)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid hexadecimal key.'}), 400

    # Retrieve ciphertext based on input_format
    if input_format == 'file':
        if 'ciphertext' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
        file = request.files['ciphertext']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file.'}), 400
        if file and allowed_file(file.stream, file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            logger.info(f"File uploaded for decryption: {filename} from {request.remote_addr}")

            # Process the file (in-memory)
            try:
                content = file.read().decode('utf-8').strip()
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File contains invalid UTF-8 characters.'}), 400

            # Ensure content is valid ASCII
            try:
                content.encode('ascii')
            except UnicodeEncodeError:
                return jsonify({'success': False, 'message': 'File contains non-ASCII characters.'}), 400

            # Directly convert hex to binary without re-conversion
            try:
                message_bin = hex_to_bin(content)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Failed to convert hex to binary: {str(e)}'}), 400

        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Only .txt files are allowed.'}), 400
    else:
        ciphertext = request.form.get('ciphertext', '').strip()
        if not ciphertext:
            return jsonify({'success': False, 'message': 'Ciphertext is required.'}), 400
        try:
            ciphertext_bin = convert_input(ciphertext, input_format)
            ciphertext_hex = bin_to_hex(ciphertext_bin)
        except ValueError as ve:
            return jsonify({'success': False, 'message': str(ve)}), 400

        message_bin = ciphertext_bin  # Assign the correctly converted binary

    # Ensure message is 64 bits (16 hex characters)
    if len(message_bin) != 64:
        return jsonify({'success': False, 'message': 'Ciphertext must be exactly 64 bits (16 hexadecimal characters).' }), 400

    # Perform decryption
    try:
        start_time = time.time()
        decrypted_bin, round_details = des_decrypt(message_bin, key_bin)
        end_time = time.time()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'}), 500

    decrypted_hex = bin_to_hex(decrypted_bin)
    elapsed_time = end_time - start_time

    # Optionally, convert decrypted hex back to ASCII
    try:
        decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8', errors='ignore')
    except ValueError:
        decrypted_text = 'Unable to decode decrypted text.'

    # Prepare detailed round details for frontend
    detailed_rounds = []
    for round_info in round_details:
        detailed_rounds.append({
            'round': round_info['round'],
            'subkey': round_info['subkey'],
            'left_before': round_info['left_before'],
            'right_before': round_info['right_before'],
            'expanded_right': round_info['expanded_right'],
            'xor_with_subkey': round_info['xor_with_subkey'],
            'sbox_details': round_info['sbox_details'],
            'permutation_output': round_info['permutation_output'],
            'left_after': round_info['left_after'],
            'right_after': round_info['right_after']
        })

    response = {
        'success': True,
        'decrypted_hex': decrypted_hex,
        'decrypted_text': decrypted_text,
        'round_details': detailed_rounds,  # Updated to include detailed information
        'time_taken': elapsed_time
    }
    return jsonify(response), 200

@app.route('/generate_key', methods=['GET'])
@limiter.limit("100 per day")  # Example: 100 requests per day
def generate_key_route():
    """
    Generate a random 16-character hexadecimal key, its binary, and Base64 representations.

    Returns:
        JSON response with the generated key in hex, binary, and Base64 formats.
    """
    key_hex = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    key_bin = ''.join(bin(int(c, 16))[2:].zfill(4) for c in key_hex)  # Convert each hex char to 4-bit binary
    key_bytes = bytes.fromhex(key_hex)
    key_base64 = base64.b64encode(key_bytes).decode('utf-8')

    logger.info(f"Generated key: {key_hex} ({key_bin}) {key_base64} for {request.remote_addr}")
    return jsonify({
        'key_hex': key_hex,
        'key_binary': key_bin,
        'key_base64': key_base64
    }), 200

@app.route('/convert_text_to_hex', methods=['POST'])
def convert_text_to_hex_route():
    """
    Convert ASCII text to hexadecimal.

    Expects JSON with:
    - 'text': string

    Returns:
        JSON response with the hexadecimal representation.
    """
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'success': False, 'message': 'Text is required.'}), 400

    text = data['text']
    try:
        # Ensure text is ASCII
        text.encode('ascii')
        hex_str = ascii_to_hex(text)
    except UnicodeEncodeError:
        return jsonify({'success': False, 'message': 'Text contains non-ASCII characters.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Conversion failed: {str(e)}'}), 500

    return jsonify({'success': True, 'hex': hex_str}), 200

@app.route('/convert_bin_to_hex', methods=['POST'])
def convert_bin_to_hex_route():
    """
    Convert binary string to hexadecimal.

    Expects JSON with:
    - 'binary': string (64 bits)

    Returns:
        JSON response with the hexadecimal representation.
    """
    data = request.get_json()
    if not data or 'binary' not in data:
        return jsonify({'success': False, 'message': 'Binary string is required.'}), 400

    bin_str = data['binary'].strip()
    if not is_valid_binary(bin_str) or len(bin_str) != 64:
        return jsonify({'success': False, 'message': 'Binary string must be exactly 64 bits.'}), 400

    try:
        hex_str = bin_to_hex([int(bit) for bit in bin_str])
    except Exception as e:
        return jsonify({'success': False, 'message': f'Conversion failed: {str(e)}'}), 500

    return jsonify({'success': True, 'hex': hex_str}), 200



@app.route('/generate_report', methods=['POST'])
@limiter.limit("5 per hour")  # Example: 5 report generations per hour
def generate_report():
    """
    Generate a PDF report of the encryption/decryption process.

    Expects JSON with:
    - 'reportType': string ('Encryption' or 'Decryption')
    - 'roundDetails': list of round detail objects
    - 'timeTaken': float
    - 'resultHex': string

    Returns:
        PDF file as attachment.
    """
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    required_fields = ['reportType', 'roundDetails', 'timeTaken', 'resultHex']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing field: {field}'}), 400

    # Additional validation: check types
    if not isinstance(data['reportType'], str):
        return jsonify({'message': 'Invalid reportType.'}), 400
    if not isinstance(data['roundDetails'], list):
        return jsonify({'message': 'Invalid roundDetails.'}), 400
    if not isinstance(data['timeTaken'], (int, float)):
        return jsonify({'message': 'Invalid timeTaken.'}), 400
    if not isinstance(data['resultHex'], str):
        return jsonify({'message': 'Invalid resultHex.'}), 400

    # Generate PDF using ReportLab
    try:
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        styles = getSampleStyleSheet()
        styleN = styles['Normal']
        styleH = styles['Heading1']

        # Title
        p.setFont("Helvetica-Bold", 20)
        p.drawCentredString(width / 2, height - 50, f"{data['reportType']} Report")

        # Time Taken
        p.setFont("Helvetica", 12)
        p.drawString(50, height - 100, f"Time Taken: {data['timeTaken']:.6f} seconds")

        # Result
        p.drawString(50, height - 120, f"{data['reportType']} Result (Hex): {data['resultHex']}")

        # Round Details
        p.setFont("Helvetica-Bold", 14)
        p.drawString(50, height - 150, "Round Details:")

        y = height - 170
        p.setFont("Helvetica", 10)
        for round_detail in data['roundDetails']:
            # Validate round_detail structure
            if not all(k in round_detail for k in ('round', 'subkey', 'left_before', 'right_before')):
                return jsonify({'message': 'Invalid roundDetails structure.'}), 400

            p.drawString(60, y, f"Round {round_detail['round']}:")
            y -= 15

            # Convert integers to strings before joining
            subkey_str = ''.join(str(bit) for bit in round_detail['subkey'])
            left_str = ''.join(str(bit) for bit in round_detail['left_before'])
            right_str = ''.join(str(bit) for bit in round_detail['right_before'])

            p.drawString(80, y, f"Subkey: {subkey_str}")
            y -= 12
            p.drawString(80, y, f"Left: {left_str}")
            y -= 12
            p.drawString(80, y, f"Right: {right_str}")
            y -= 20  # Space between rounds

            if y < 50:
                p.showPage()
                y = height - 50

        p.showPage()
        p.save()
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{data['reportType']}_Report.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({'message': f'Failed to generate report: {str(e)}'}), 500
