
# Lab 5 - Classical Digital Signatures

Họ tên: Trần Ngọc Nhất
MSSV: 24162086



## Goals

This project implements a CLI signature tool for Lab 5:

- ECDSA-P256 key generation

- ECDSA-P384 key generation

- RSA-PSS-3072 key generation

- PEM and DER key export

- Detached signing and verification will be added next

- Negative tests and benchmarks will be added next



## Build on Windows MSYS2 UCRT64



```bash

cmake -S . -B build-windows-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Release

cmake --build build-windows-ucrt64

./build-windows-ucrt64/sigtool.exe version

