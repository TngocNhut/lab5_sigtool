#!/usr/bin/env bash
set -euo pipefail

BIN="./build-windows-ucrt64/sigtool.exe"
ART="artifacts/windows"

mkdir -p "$ART/keys" "$ART/signatures" "$ART/benchmark"

echo "===== LAB 5 WINDOWS DEMO ====="

echo
echo "===== VERSION ====="
$BIN version

echo
echo "===== KEYGEN ====="
$BIN keygen --algo ecdsa-p256 \
  --pub "$ART/keys/demo_ecdsa_p256_pub.pem" \
  --priv "$ART/keys/demo_ecdsa_p256_priv.pem"

$BIN keygen --algo ecdsa-p384 \
  --pub "$ART/keys/demo_ecdsa_p384_pub.pem" \
  --priv "$ART/keys/demo_ecdsa_p384_priv.pem"

$BIN keygen --algo rsa-pss-3072 \
  --pub "$ART/keys/demo_rsa_pss_3072_pub.pem" \
  --priv "$ART/keys/demo_rsa_pss_3072_priv.pem"

echo
echo "===== KEYINFO ====="
$BIN keyinfo --pub "$ART/keys/demo_ecdsa_p256_pub.pem"
$BIN keyinfo --pub "$ART/keys/demo_ecdsa_p384_pub.pem"
$BIN keyinfo --pub "$ART/keys/demo_rsa_pss_3072_pub.pem"

echo
echo "===== MESSAGE ====="
cat > samples/demo_message.txt <<'TXT'
Lab 5 Windows demo message.
Student: Tran Ngoc Nhat.
Purpose: detached ECDSA and RSA-PSS signatures.
TXT

cat samples/demo_message.txt

echo
echo "===== ECDSA-P256 SIGN / VERIFY ====="
$BIN sign \
  --algo ecdsa-p256 \
  --priv "$ART/keys/demo_ecdsa_p256_priv.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p256.sig"

$BIN verify \
  --algo ecdsa-p256 \
  --pub "$ART/keys/demo_ecdsa_p256_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p256.sig"

echo
echo "===== ECDSA-P384 SIGN / VERIFY ====="
$BIN sign \
  --algo ecdsa-p384 \
  --priv "$ART/keys/demo_ecdsa_p384_priv.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p384.sig"

$BIN verify \
  --algo ecdsa-p384 \
  --pub "$ART/keys/demo_ecdsa_p384_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p384.sig"

echo
echo "===== RSA-PSS-3072 SIGN / VERIFY ====="
$BIN sign \
  --algo rsa-pss-3072 \
  --priv "$ART/keys/demo_rsa_pss_3072_priv.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_rsa_pss_3072.sig"

$BIN verify \
  --algo rsa-pss-3072 \
  --pub "$ART/keys/demo_rsa_pss_3072_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_rsa_pss_3072.sig"

echo
echo "===== NEGATIVE TEST: TAMPERED MESSAGE ====="
cp samples/demo_message.txt samples/demo_message_tampered.txt
echo "TAMPERED DATA" >> samples/demo_message_tampered.txt

set +e
$BIN verify \
  --algo ecdsa-p256 \
  --pub "$ART/keys/demo_ecdsa_p256_pub.pem" \
  --in samples/demo_message_tampered.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p256.sig"
tampered_msg_rc=$?
set -e

if [[ "$tampered_msg_rc" -eq 0 ]]; then
  echo "[FAIL] Tampered message unexpectedly verified"
  exit 1
fi

echo "[OK] Tampered message rejected"

echo
echo "===== NEGATIVE TEST: TAMPERED SIGNATURE ====="
cp "$ART/signatures/demo_message_rsa_pss_3072.sig" \
   "$ART/signatures/demo_message_rsa_pss_3072_tampered.sig"

python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/signatures/demo_message_rsa_pss_3072_tampered.sig")
data = bytearray(p.read_bytes())
data[0] ^= 0x01
p.write_bytes(data)
print("[OK] Tampered RSA-PSS signature")
PY

set +e
$BIN verify \
  --algo rsa-pss-3072 \
  --pub "$ART/keys/demo_rsa_pss_3072_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_rsa_pss_3072_tampered.sig"
tampered_sig_rc=$?
set -e

if [[ "$tampered_sig_rc" -eq 0 ]]; then
  echo "[FAIL] Tampered signature unexpectedly verified"
  exit 1
fi

echo "[OK] Tampered signature rejected"

echo
echo "===== NEGATIVE TEST: WRONG PUBLIC KEY ====="
$BIN keygen --algo ecdsa-p256 \
  --pub "$ART/keys/demo_wrong_ecdsa_p256_pub.pem" \
  --priv "$ART/keys/demo_wrong_ecdsa_p256_priv.pem"

set +e
$BIN verify \
  --algo ecdsa-p256 \
  --pub "$ART/keys/demo_wrong_ecdsa_p256_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_ecdsa_p256.sig"
wrong_key_rc=$?
set -e

if [[ "$wrong_key_rc" -eq 0 ]]; then
  echo "[FAIL] Wrong public key unexpectedly verified"
  exit 1
fi

echo "[OK] Wrong public key rejected"

echo
echo "===== NEGATIVE TEST: UNSUPPORTED ALGORITHM ====="
set +e
$BIN sign \
  --algo dsa-1024 \
  --priv "$ART/keys/demo_ecdsa_p256_priv.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/bad_algo.sig"
bad_algo_rc=$?
set -e

if [[ "$bad_algo_rc" -eq 0 ]]; then
  echo "[FAIL] Unsupported algorithm unexpectedly accepted"
  exit 1
fi

echo "[OK] Unsupported algorithm rejected"

echo
echo "===== SIGNATURE BENCHMARK ====="
$BIN bench --out "$ART/benchmark/demo_bench_signatures_windows.csv" \
  > "$ART/benchmark/demo_bench_signatures_windows.log" 2>&1

grep "avg_ms\|Signature benchmark completed" "$ART/benchmark/demo_bench_signatures_windows.log"
cat "$ART/benchmark/demo_bench_signatures_windows.csv"

echo
echo "[OK] Lab 5 Windows demo completed successfully."
