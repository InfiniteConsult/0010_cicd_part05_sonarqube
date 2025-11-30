#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               02-build-image.sh
#
#  This is the "Builder" script for SonarQube.
#  It creates a custom image that trusts our Local Root CA.
#
#  1. Staging: Copies ca.pem from the CA directory to CURRENT dir.
#  2. Build: Creates 'sonarqube-custom:latest' from context '.'.
#
# -----------------------------------------------------------

set -e

# --- 1. Define Paths ---
CA_SOURCE="$HOME/cicd_stack/ca/pki/certs/ca.pem"

echo "Starting SonarQube Custom Build..."

# --- 2. Stage Assets ---
if [ ! -f "$CA_SOURCE" ]; then
    echo "ERROR: CA certificate not found at $CA_SOURCE"
    exit 1
fi

echo "Copying CA certificate to build context (current dir)..."
cp "$CA_SOURCE" ./ca.pem

# --- 3. Build Image ---
echo "Building 'sonarqube-custom:latest'..."

# We build from the current directory where the Dockerfile resides
docker build -t sonarqube-custom:latest .

# Cleanup staged file
rm ./ca.pem

echo "Build complete."
echo "   Image: sonarqube-custom:latest"
echo "   Ready to run 03-deploy-sonarqube.sh"