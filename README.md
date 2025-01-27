# How to Run the RSA Blind Signature Implementation

1. Prerequisites:
   - Python 3.7 or higher installed on your computer
   - Required packages: cryptography
   
2. Install Required Package:
   ```bash
   pip install cryptography
   ```

3. Run the Program:
   - Open a terminal/command prompt in the folder containing blind_signature_implementation.py
   - Run the command:
   ```bash
   python blind_signature_implementation.py
   ```

4. Using the Program:
   - Enter a message in the text field
   - Follow the process step by step:
     1. Click "Blind Message" to blind your message
     2. Click "Sign Blinded Message" to sign it
     3. Click "Unblind Signature" to reveal the final signature
     4. Click "Verify Signature" to verify the result
   
   The status and results will be displayed in the GUI window.

5. Key Information:
   - The program generates a new 2048-bit RSA key pair each time it runs
   - The public key information is displayed in the GUI
   - All intermediate results are shown in the results display area

6. Running Tests:
   The program includes automated tests to verify its functionality. To run these tests:
   
   - Ensure you have the `unittest` framework (pre-installed with Python)
   - Run the following command in the terminal:
     ```bash
     python -m unittest test_blind_signature.py
     ```
   
   The tests cover the following cases:
   - Basic functionality: Blinding, signing, unblinding, and verifying messages
   
   Expected output:
   ```
   ....
   ----------------------------------------------------------------------
   Ran 4 tests in 0.XXXs

   OK
   ```

   If any test fails, review the error messages for debugging guidance.
