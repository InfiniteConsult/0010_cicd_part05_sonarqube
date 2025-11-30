#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               02-deploy-sonarqube.sh
#
#  This is the "Launcher" script for SonarQube Community Build.
#  It performs a clean-slate deployment of the container.
#
#  1. Clean Slate: Stops/Removes existing container.
#  2. Volumes: Ensures data, extensions, and logs volumes exist.
#  3. Launch: Runs sonarqube:community with strict networking.
#
# -----------------------------------------------------------

set -e

# --- 1. Define Paths ---
HOST_CICD_ROOT="$HOME/cicd_stack"
SONAR_BASE="$HOST_CICD_ROOT/sonarqube"
SCOPED_ENV_FILE="$SONAR_BASE/sonarqube.env"

echo "Starting SonarQube Deployment..."

# --- 2. Prerequisite Checks ---
if [ ! -f "$SCOPED_ENV_FILE" ]; then
    echo "ERROR: Scoped env file not found at $SCOPED_ENV_FILE"
    echo "Please run 01-setup-sonarqube.sh first."
    exit 1
fi

# --- 3. Clean Slate Protocol ---
if [ "$(docker ps -q -f name=sonarqube)" ]; then
    echo "Stopping existing 'sonarqube' container..."
    docker stop sonarqube
fi
if [ "$(docker ps -aq -f name=sonarqube)" ]; then
    echo "Removing existing 'sonarqube' container..."
    docker rm sonarqube
fi

# --- 4. Volume Management ---
# We ensure all three required storage lockers exist.
# Using hyphens to match our established convention (Article 5).

echo "Verifying Docker volumes..."
docker volume create sonarqube-data > /dev/null
docker volume create sonarqube-extensions > /dev/null
docker volume create sonarqube-logs > /dev/null
echo "Volumes verified."

# --- 5. Deploy Container ---
echo "Launching SonarQube Community Build..."

# Notes on Configuration:
# - We use --env-file to inject the JDBC credentials securely.
# - We use 'sonarqube:community' to target the specific edition.
# - We bind to 127.0.0.1 to strictly limit access to the host.

docker run -d \
  --name sonarqube \
  --restart always \
  --network cicd-net \
  --hostname sonarqube.cicd.local \
  --publish 127.0.0.1:9000:9000 \
  --env-file "$SCOPED_ENV_FILE" \
  --volume sonarqube-data:/opt/sonarqube/data \
  --volume sonarqube-extensions:/opt/sonarqube/extensions \
  --volume sonarqube-logs:/opt/sonarqube/logs \
  sonarqube:community

echo "SonarQube container started."
echo "   It will take 2-3 minutes to initialize Elasticsearch."
echo "   Monitor logs with: docker logs -f sonarqube"
echo ""
echo "   Wait for: 'SonarQube is operational'"
echo "   Then access: http://sonarqube.cicd.local:9000"