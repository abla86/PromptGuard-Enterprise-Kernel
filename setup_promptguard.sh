#!/usr/bin/env bash
set -e

echo "================================================================="
echo " 🛡️  CREATING PROMPTGUARD-TAINT ENTERPRISE PROJECT STRUCTURE"
echo "================================================================="

mkdir -p promptguard/core promptguard/middleware tests

echo "[+] Created directories: promptguard/core, promptguard/middleware, tests"

echo "[+] PromptGuard Enterprise project initialized successfully."
