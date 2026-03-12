#!/usr/bin/env bash
# Generate a synthetic ICAO 9303 e2e test dataset using ECDSA P-256.
#
# Creates: CSCA cert (EC P-256), DS cert (signed by CSCA with ECDSA-SHA256),
# and EF_SOD.bin (CMS-signed LdsSecurityObject with ECDSA-SHA256).
#
# Requirements: OpenSSL 3.x, Python 3
#
# Usage: ./tests/gen-synthetic-dataset-ecdsa.sh [output_dir]
#   Default output: tests/dataset-synth-ecdsa/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/tests/dataset-synth-ecdsa}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BSI_DATASET="$REPO_ROOT/tests/dataset"

echo "==> Generating synthetic ICAO 9303 ECDSA P-256 dataset"
echo "    BSI DGs:  $BSI_DATASET"
echo "    Output:   $OUT_DIR"
echo "    Work dir: $WORK"

# ── 1. Generate CSCA (Country Signing CA) with EC P-256 ─────────────────────
echo "--- Generating CSCA key + self-signed cert (EC P-256, ECDSA-SHA256) ---"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/csca-key.pem" 2>/dev/null
openssl req -new -x509 \
    -key "$WORK/csca-key.pem" \
    -out "$WORK/csca.pem" \
    -days 3650 \
    -subj "/C=ZZ/O=Synthetic CSCA ECDSA/CN=Test Country Signing CA (P-256)" \
    -sha256 \
    2>/dev/null

# ── 2. Generate DS (Document Signer) signed by CSCA ─────────────────────────
echo "--- Generating DS key + cert signed by CSCA (EC P-256, ECDSA-SHA256) ---"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ds-key.pem" 2>/dev/null
openssl req -new \
    -key "$WORK/ds-key.pem" \
    -out "$WORK/ds.csr" \
    -subj "/C=ZZ/O=Synthetic DS ECDSA/CN=Test Document Signer (P-256)" \
    -sha256 \
    2>/dev/null
openssl x509 -req \
    -in "$WORK/ds.csr" \
    -CA "$WORK/csca.pem" \
    -CAkey "$WORK/csca-key.pem" \
    -CAcreateserial \
    -out "$WORK/ds.pem" \
    -days 1825 \
    -sha256 \
    2>/dev/null

# Verify chain
openssl verify -CAfile "$WORK/csca.pem" "$WORK/ds.pem" >/dev/null
echo "    Chain verified: CSCA -> DS"

# ── 3. Build LdsSecurityObject DER ──────────────────────────────────────────
echo "--- Building LdsSecurityObject (SHA-256 hashes of BSI DGs 1,2,3,4,14) ---"

python3 -c "
import hashlib, sys, os

def sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).digest()

def encode_length(l):
    if l < 128:
        return bytes([l])
    elif l < 256:
        return bytes([0x81, l])
    else:
        return bytes([0x82, (l >> 8) & 0xff, l & 0xff])

bsi = sys.argv[1]
out = sys.argv[2]

# Hash each DG
dg_files = {
    1:  os.path.join(bsi, 'Datagroup1.bin'),
    2:  os.path.join(bsi, 'Datagroup2.bin'),
    3:  os.path.join(bsi, 'Datagroup3.bin'),
    4:  os.path.join(bsi, 'Datagroup4.bin'),
    14: os.path.join(bsi, 'Datagroup14.bin'),
}

dg_hashes = {}
for dg_num, path in sorted(dg_files.items()):
    dg_hashes[dg_num] = sha256_file(path)
    print(f'    DG{dg_num:2d}: {dg_hashes[dg_num].hex()}')

# SHA-256 AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
sha256_algid = bytes([
    0x30, 0x0d,
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00,
])

# Build DataGroupHash entries
dg_entries = b''
for dg_num, dg_hash in sorted(dg_hashes.items()):
    integer = bytes([0x02, 0x01, dg_num])
    octet_string = bytes([0x04, 0x20]) + dg_hash
    entry = bytes([0x30, len(integer) + len(octet_string)]) + integer + octet_string
    dg_entries += entry

dg_hash_values = bytes([0x30]) + encode_length(len(dg_entries)) + dg_entries

# LdsSecurityObject: SEQUENCE { INTEGER 0, AlgId, DataGroupHashValues }
version = bytes([0x02, 0x01, 0x00])
content = version + sha256_algid + dg_hash_values
lso = bytes([0x30]) + encode_length(len(content)) + content

lso_path = os.path.join(out, 'lso.der')
with open(lso_path, 'wb') as f:
    f.write(lso)
print(f'    LdsSecurityObject: {len(lso)} bytes -> {lso_path}')
" "$BSI_DATASET" "$WORK"

# ── 4. CMS sign the LdsSecurityObject with DS key (ECDSA-SHA256) ────────────
echo "--- CMS signing LdsSecurityObject (ECDSA-SHA256, ICAO content type) ---"
openssl cms -sign -binary -nodetach \
    -in "$WORK/lso.der" \
    -signer "$WORK/ds.pem" \
    -inkey "$WORK/ds-key.pem" \
    -outform DER \
    -out "$WORK/cms_signed.der" \
    -md sha256 \
    -econtent_type 2.23.136.1.1.1 \
    2>/dev/null
echo "    CMS SignedData: $(wc -c < "$WORK/cms_signed.der" | tr -d ' ') bytes"

# ── 5. Wrap in ICAO Application tag 23 (0x77) ───────────────────────────────
echo "--- Wrapping in ICAO EF_SOD (Application tag 23) ---"
python3 -c "
import sys

with open(sys.argv[1], 'rb') as f:
    cms = f.read()

def encode_length(l):
    if l < 128:
        return bytes([l])
    elif l < 256:
        return bytes([0x81, l])
    else:
        return bytes([0x82, (l >> 8) & 0xff, l & 0xff])

ef_sod = bytes([0x77]) + encode_length(len(cms)) + cms

with open(sys.argv[2], 'wb') as f:
    f.write(ef_sod)
print(f'    EF_SOD.bin: {len(ef_sod)} bytes')
" "$WORK/cms_signed.der" "$WORK/EF_SOD.bin"

# ── 6. Export DER certs and copy to output ───────────────────────────────────
openssl x509 -in "$WORK/csca.pem" -outform DER -out "$WORK/CSCA.cer"
openssl x509 -in "$WORK/ds.pem"   -outform DER -out "$WORK/DSC.cer"

mkdir -p "$OUT_DIR"
cp "$WORK/EF_SOD.bin" "$WORK/CSCA.cer" "$WORK/DSC.cer" "$OUT_DIR/"

echo ""
echo "==> Synthetic ECDSA P-256 dataset generated in $OUT_DIR/"
echo "    CSCA.cer    - Self-signed Country Signing CA (EC P-256)"
echo "    DSC.cer     - Document Signer cert signed by CSCA (ECDSA-SHA256)"
echo "    EF_SOD.bin  - CMS-signed LdsSecurityObject with BSI DG hashes"
echo ""
echo "    Use with BSI DG files from tests/dataset/ for full e2e PA:"
echo "    Step 1: SOD signature verification (DS cert signs LdsSecurityObject)"
echo "    Step 2: DG hash integrity (SHA-256 of DGs 1,2,3,4,14)"
echo "    Step 3: DS cert chain verification (DS cert signed by CSCA)"
