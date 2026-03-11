# Malaysian Passport Dataset

Real Malaysian passport data extracted from the
[gmrtd](https://github.com/niclas-ahden/gmrtd) project's test fixtures.

## Contents

- `CSCA.cer` — Malaysian Country Signing CA certificate (3072-bit RSA, self-signed, valid 2019-2029)
- `DSC.cer` — Document Signer certificate signed by CSCA
- `EF_SOD.bin` — Document Security Object (CMS SignedData, RSA-PSS-SHA256, 2048-bit DS key)
- `expDg1Hash.bin` — Expected SHA-256 hash of DG1 (32 bytes)
- `expDg2Hash.bin` — Expected SHA-256 hash of DG2 (32 bytes)

## Notes

This dataset has SOD + CSCA but **no DG binaries** — only expected hashes.
This means steps 1+3 of Passive Authentication can be tested (SOD signature
verification + cert chain to CSCA), but not step 2 (DG hash integrity).

Used by `test_my_full_passive_auth` in `src/crypto/certificate.rs` to verify
the 3072-bit CSCA → DS certificate chain.
