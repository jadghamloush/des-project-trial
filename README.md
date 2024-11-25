# DES Encryption & Decryption Tool

**A secure and user-friendly web application for encrypting and decrypting messages using the Data Encryption Standard (DES) algorithm.**

**Built with:**

* **Frontend:** React, Formik, Yup, React Bootstrap, Axios
* **Backend:** Flask, Flask-CORS, Flask-Limiter, ReportLab, python-magic

## Features

* **Secure Encryption & Decryption:** Utilizes DES for secure message encryption and decryption.
* **Multiple Input Formats:** Supports data in hexadecimal, ASCII text, binary strings, and `.txt` file uploads.
* **User-Friendly Interface:** Intuitive forms with real-time validation and feedback.
* **Detailed Process Insights:** View round-by-round details of encryption/decryption.
* **Report Generation:** Generate and download PDF reports summarizing your sessions.
* **Error Handling & Validation:** Comprehensive validation on both frontend and backend ensures data integrity.
* **Responsive Design:** Optimized for various devices and screen resolutions.

## Installation

### Prerequisites

* **Node.js** (v14 or later) & **npm**: [Download Node.js](https://nodejs.org/)
* **Python** (v3.8 or later) & **pip**: [Download Python](https://www.python.org/downloads/)
* **Git**: [Download Git](https://git-scm.com/)

### Backend Setup

1. **Clone the Repository:**

   ```bash
   git clone [https://github.com/nadermasri/des-crypto.git](https://github.com/nadermasri/des-crypto.git)
   cd des-crypto/backend
   ```

2. **Create a Virtual Environment:**

   ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Backend Dependencies:**

   ```bash
    pip install -r requirements.txt
   ```

4. **Run the Backend Server:**

   ```bash
    flask run
   ```

   The backend server will start on http://localhost:5000/.

### Frontend Setup

1.  **Navigate to the Frontend Directory:**

```bash
cd ../frontend
```

2: **Install Frontend Dependencies**

```bash
npm install
```

3. **Run the Frontend Development Server**

```bash
npm start
```
## Usage

Once both the frontend and backend servers are running, you can access the application via http://localhost:3000/. The interface provides two main functionalities: Encryption and Decryption.

### Encryption
1. **Navigate to the Encryption Page:**

   Click on the Encryption tab or navigate to http://localhost:3000/encryption.

2. **Select Input Format:**

   Choose your preferred input format from the dropdown:
   - **Hexadecimal**: Enter a 16-character hexadecimal string.
   - **ASCII Text**: Enter any ASCII text.
   - **Binary**: Enter a 64-bit binary string.
   - **File Upload (.txt)**: Upload a .txt file containing a 16-character hexadecimal string.

3. **Enter the Key:**

   Provide a 16-character hexadecimal key. You can generate a random key using the Generate Key feature or enter your own.

4. **Submit the Form:**

   Click the **Encrypt** button. Upon successful encryption, the ciphertext, round details, and time taken will be displayed. You can also generate a PDF report of the session.

### Decryption
1. **Navigate to the Decryption Page:**

   Click on the Decryption tab or navigate to http://localhost:3000/decryption.

2. **Select Input Format:**

   Choose your preferred input format from the dropdown:
   - **Hexadecimal**: Enter a 16-character hexadecimal ciphertext.
   - **ASCII Text**: Enter the ciphertext in ASCII.
   - **Binary**: Enter a 64-bit binary ciphertext string.
   - **File Upload (.txt)**: Upload a .txt file containing a 16-character hexadecimal ciphertext.

3. **Enter the Key:**

   Provide the 16-character hexadecimal key used during encryption.

4. **Submit the Form:**

   Click the **Decrypt** button. Upon successful decryption, the plaintext, round details, and time taken will be displayed. You can also generate a PDF report of the session.
## API Endpoints

### /encrypt (POST)
- **Description**: Encrypts a plaintext message using DES.
- **Request Parameters**:
  - `key` (string, required): 16-character hexadecimal key.
  - `input_format` (string, required): One of ['hex', 'text', 'binary', 'file'].
  - `message` (string/file, required): The plaintext message in the specified format.
- **Response**:
  - `success` (boolean): Indicates success or failure.
  - `ciphertext` (string): The resulting ciphertext in hexadecimal format.
  - `round_details` (array): Details of each encryption round.
  - `time_taken` (float): Time taken for the encryption process in seconds.

### /decrypt (POST)
- **Description**: Decrypts a ciphertext message using DES.
- **Request Parameters**:
  - `key` (string, required): 16-character hexadecimal key.
  - `input_format` (string, required): One of ['hex', 'text', 'binary', 'file'].
  - `ciphertext` (string/file, required): The ciphertext message in the specified format.
- **Response**:
  - `success` (boolean): Indicates success or failure.
  - `decrypted_hex` (string): The decrypted message in hexadecimal format.
  - `decrypted_text` (string): The decrypted plaintext message.
  - `round_details` (array): Details of each decryption round.
  - `time_taken` (float): Time taken for the decryption process in seconds.

### /generate_key (GET)
- **Description**: Generates a random 16-character hexadecimal key.
- **Response**:
  - `key` (string): The generated hexadecimal key.

### /convert_text_to_hex (POST)
- **Description**: Converts ASCII text to hexadecimal.
- **Request Body**:
  - `text` (string, required): The ASCII text to convert.
- **Response**:
  - `success` (boolean): Indicates success or failure.
  - `hex` (string): The resulting hexadecimal string.

### /convert_bin_to_hex (POST)
- **Description**: Converts a binary string to hexadecimal.
- **Request Body**:
  - `binary` (string, required): The 64-bit binary string to convert.
- **Response**:
  - `success` (boolean): Indicates success or failure.
  - `hex` (string): The resulting hexadecimal string.

### /generate_report (POST)
- **Description**: Generates a PDF report of the encryption/decryption process.
- **Request Body**:
  - `reportType` (string, required): Either 'Encryption' or 'Decryption'.
  - `roundDetails` (array, required): Details of each encryption/decryption round.
  - `timeTaken` (float, required): Time taken for the process.
  - `resultHex` (string, required): The resulting hexadecimal string.
- **Response**:
  - Returns a PDF file as an attachment.
