# Blind Signature Demonstration

## Overview
This project implements two blind signature schemes: 
- RSA Blind Signature 
- Schnorr Blind Signature (using Elliptic Curve)

Blind signatures allow a message to be signed without revealing its contents to the signer, providing privacy and untraceability.

## Features
- Interactive GUI for demonstrating blind signature protocols
- Supports both RSA and Schnorr signature schemes
- Full implementation of blinding, signing, and verification processes
- Displays cryptographic key information in the GUI
- Comprehensive test suite to validate cryptographic operations

## Prerequisites
- Python 3.7 or higher
- Libraries:
  - `tkinter` for GUI
  - `cryptography` for cryptographic primitives
  - `unittest` for testing

## Installation
1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## How to Run the Blind Signature Implementation

### Running the Program
1. Open a terminal/command prompt in the project folder
2. Run the command:
```bash
python blind_signature_implementation.py
```
3. A graphical interface (GUI) will open, allowing you to test blind signature protocols interactively.

### Using the RSA Blind Signature
1. Select "RSA" in the Signature Scheme section
2. Enter a message in the text field
3. Follow the process step by step:
   - Click "Blind Message" to blind your message
   - Click "Sign Blinded Message" to sign it
   - Click "Unblind Signature" to reveal the final signature
   - Click "Verify Signature" to verify the result
4. The public key parameters (exponent `e` and modulus `n`) will be displayed in the GUI.

### Using the Schnorr Blind Signature
1. Select "Schnorr" in the Signature Scheme section
2. **Click "Generate k" first** (this step is mandatory before blinding the message).
3. Enter a message in the text field
4. Follow the process step by step:
   - Click "Blind Message" to blind your message
   - Click "Sign Blinded Message" to sign it
   - Click "Unblind Signature" to reveal the final signature
   - Click "Verify Signature" to verify the result
5. The public key and elliptic curve parameters will be displayed in the GUI.

### Key Information
- Generates new cryptographic keys each time it runs
- Public key information is displayed in the GUI, including:
  - RSA: Public exponent (`e`) and modulus (`n`)
  - Schnorr: Elliptic curve public key coordinates (X, Y)
- Intermediate results, such as blinded messages and signatures, are displayed in the results section

### Understanding the GUI Output
- **Blinded Message**: The message after applying the blinding factor
- **Blind Signature**: The signature on the blinded message
- **Final Signature**: The unblinded signature, ready for verification
- **Verification Status**: Displays whether the signature verification passed or failed

## Detailed Test Cases for Blind Signature Implementation

### RSA Blind Signature Tests
1. **Signature Flow Test** (`test_signature_flow`):
   - Verifies complete blind signature process
   - Steps tested:
     * Blinding the message
     * Signing the blinded message
     * Unblinding the signature
     * Verifying the final signature
   - Checks that each step returns correct data types
   - Ensures signature verification succeeds

2. **Error Handling Tests**:
   a. **Signing Without Blinding** (`test_sign_without_blind_message`):
      - Attempts to sign without first blinding a message
      - Expects `ValueError` to be raised
   
   b. **Unblinding Without Signature** (`test_unblind_without_signature`):
      - Tries to unblind before completing the signing process
      - Expects `ValueError` to be raised

3. **Signature Integrity Test** (`test_verify_with_wrong_signature`):
   - Modifies the signature slightly
   - Confirms verification fails with an altered signature

4. **Performance Test** (`test_performance_with_various_message_sizes`):
   - Checks that the implementation can handle messages of varying lengths efficiently
   - Ensures correct processing for short, medium, and long messages

### Schnorr Blind Signature Tests
1. **Signature Flow Test** (`test_signature_flow`):
   - Validates complete Schnorr blind signature process
   - Tests:
     * Generating R point
     * Blinding the message
     * Signing the blinded message
     * Unblinding the signature
     * Verifying the final signature

2. **Error Handling Tests**:
   a. **Blinding Without Generating k** (`test_blind_message_without_generate_k`):
      - Attempts to blind a message before generating R point
      - Expects `ValueError`
   
   b. **Signing Without Blinding** (`test_sign_blinded_without_blinding`):
      - Tries to sign without first blinding the message
      - Expects `ValueError`

   c. **Unblinding Without Signing** (`test_unblind_without_sign`):
      - Attempts to unblind before completing the signing process
      - Expects `ValueError`

3. **Signature Integrity Test** (`test_verify_with_wrong_signature`):
   - Modifies the signature slightly
   - Ensures verification fails with an altered signature

4. **Performance Test** (`test_performance_with_various_message_sizes`):
   - Checks performance for short, medium, and long messages
   - Ensures signing and verification work consistently for different message lengths

### Test Execution
- Framework: Python's `unittest`
- Total Test Cases: 11
- Covers both RSA and Schnorr signature schemes
- Tests functional correctness, error handling, and performance

### Running Tests
```bash
python -m unittest test_blind_signature.py
```
### Expected Output
```
...........
----------------------------------------------------------------------
Ran 11 tests in 0.XXXs

OK
```
### Troubleshooting
- If tests fail, carefully review:
  * Error messages
  * Specific test case that failed
  * Potential implementation issues

## Components
- `blind_signature_implementation.py`: Main implementation
  - `SchnorrBlindSignature`: Elliptic curve blind signature class
  - `RSABlindSignature`: RSA blind signature class
  - `BlindSignatureGUI`: Tkinter-based user interface
- `test_blind_signature.py`: Unit tests for both signature schemes

