#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               05-update-jenkins.sh
#
#  This script integrates Jenkins with SonarQube.
#
#  1. Secrets: Reads SONAR_ADMIN_TOKEN (host) -> Injects SONAR_AUTH_TOKEN (jenkins.env).
#  2. JCasC:   Runs local python helper to patch jenkins.yaml in cicd_stack.
#  3. Apply:   Triggers Jenkins redeployment from the Jenkins article dir.
#
# -----------------------------------------------------------

set -e

# --- Paths ---
CICD_ROOT="$HOME/cicd_stack"
# The module where the Jenkins deployment logic lives
JENKINS_MODULE_DIR="$HOME/Documents/FromFirstPrinciples/articles/0008_cicd_part04_jenkins"
JENKINS_ENV_FILE="$JENKINS_MODULE_DIR/jenkins.env"
DEPLOY_SCRIPT="$JENKINS_MODULE_DIR/03-deploy-controller.sh"

# Local python helper
PY_HELPER="./update_jcasc_sonar.py"
MASTER_ENV="$CICD_ROOT/cicd.env"

echo "Starting Jenkins <-> SonarQube Integration..."

# --- 1. Secret Injection ---
if [ ! -f "$MASTER_ENV" ]; then
    echo "ERROR: Master environment file not found: $MASTER_ENV"
    exit 1
fi

# Load SONAR_ADMIN_TOKEN
source "$MASTER_ENV"

if [ -z "$SONAR_ADMIN_TOKEN" ]; then
    echo "ERROR: SONAR_ADMIN_TOKEN not found in cicd.env."
    echo "       Please generate a User Token in SonarQube (My Account > Security)"
    echo "       and save it to ~/cicd_stack/cicd.env"
    exit 1
fi

if [ ! -f "$JENKINS_ENV_FILE" ]; then
    echo "ERROR: Jenkins env file not found at: $JENKINS_ENV_FILE"
    exit 1
fi

echo "Injecting SonarQube secrets into jenkins.env..."

# Idempotency check using grep to prevent duplicate entries
if ! grep -q "SONAR_AUTH_TOKEN" "$JENKINS_ENV_FILE"; then
cat << EOF >> "$JENKINS_ENV_FILE"

# --- SonarQube Integration ---
SONAR_AUTH_TOKEN=$SONAR_ADMIN_TOKEN
EOF
    echo "Secrets injected."
else
    echo "Secrets already present."
fi

# --- 2. Update JCasC ---
echo "Updating JCasC configuration..."
if [ ! -f "$PY_HELPER" ]; then
    echo "ERROR: Python helper script not found at $PY_HELPER"
    exit 1
fi

python3 "$PY_HELPER"

# --- 3. Re-Deploy Jenkins ---
echo "Triggering Jenkins Re-deployment (Container Recreate)..."

if [ ! -x "$DEPLOY_SCRIPT" ]; then
    echo "ERROR: Deploy script not found or not executable: $DEPLOY_SCRIPT"
    exit 1
fi

# Execute the deploy script from its own directory context
# This ensures it finds the Dockerfile and other assets correctly
(cd "$JENKINS_MODULE_DIR" && ./03-deploy-controller.sh)

echo "Integration update complete."
echo "Jenkins is restarting. Wait for initialization."