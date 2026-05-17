# Secure Biometric Vault Web

Flask web version of the Biometrie & Tatouage Numerique university demo.

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
2. Accept the RGPD consent checkbox.
3. Login with the same username and fingerprint image.
4. Open Biometric Analysis to show preprocessing, skeletonization, Crossing Number minutiae, `Nref`, `Ntest`, `Nmatch`, `score_min`, `score_dice`, `score_geo`, threshold and decision.
5. Open Performance to choose the matching threshold: low `0.60`, medium `0.75`, or high `0.85`.
6. Open Watermark to extract and validate the hidden LSB message.
7. Open Watermark Evaluation to calculate PSNR, BER, NC and payload.
8. Open Watermark Attacks to test JPEG compression, noise, resize and crop.
9. Open Security Model to explain DICAN controls.
10. Open Database Attack to show what a stolen SQLite database exposes.
11. Encrypt `static/uploads/demo_secret.txt`.
12. Decrypt the generated file from the Decrypt page.
13. Open Attack Simulation and upload `static/uploads/demo_fingerprint2.png` three times for the same username.
14. View Logs to show failed attempts and account blocking.

## Notes

- Fingerprint image upload simulates a real scanner.
- Pillow is used to normalize, binarize and skeletonize fingerprint images before matching.
- Fingerprint matching follows the course idea: minutiae extraction with Crossing Number and score formulas.
- The login decision uses a similarity score compared with a configurable threshold.
- Files are encrypted with AES-256-GCM using PyCryptodome.
- Fingerprint templates are stored as SHA-256 hashes.
- A user can have multiple fingerprint templates in the `user_fingerprints` table.
- Watermarked fingerprint images are stored in `data/watermarked`.
- LSB watermark pages demonstrate extraction, validation, quality metrics and attack robustness.
- Security model page maps the app to DICAN, RGPD, AES, hash integrity, access control and logs.
