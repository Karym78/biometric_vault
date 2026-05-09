# Secure Biometric Vault Web

Flask web version of the biometric vault university demo.

## Run

```powershell
cd biometric_vault_web
python app.py
```

Open:

```text
http://127.0.0.1:5001
```

## Demo Flow

1. Register a user with `static/uploads/demo_fingerprint1.png`.
2. Login with the same username and fingerprint image.
3. Add a second fingerprint from the dashboard if you want to demo multi-fingerprint enrollment.
4. Encrypt `static/uploads/demo_secret.txt`.
5. Decrypt the generated `.vault` file from `data/encrypted_files`.
6. Open Attack Simulation and upload `static/uploads/demo_fingerprint2.png` three times for the same username.
7. View Logs to show failed attempts and account blocking.

## Notes

- Fingerprint image upload simulates a real scanner.
- Pillow is used to normalize fingerprint images before hashing.
- Files are encrypted with AES-256-GCM using PyCryptodome.
- Fingerprint templates are stored as SHA-256 hashes.
- A user can have multiple fingerprint templates in the `user_fingerprints` table.
- Watermarked fingerprint images are stored in `data/watermarked`.
