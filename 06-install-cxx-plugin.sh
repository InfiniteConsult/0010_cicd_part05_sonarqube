#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               06-install-cxx-plugin.sh
#
#  Installs the Community C++ Plugin (sonar-cxx) into the
#  running SonarQube container.
#
#  We do this post-deployment because the 'extensions'
#  directory is a mounted volume, which obscures any
#  plugins we might try to bake into the Docker image.
#
# -----------------------------------------------------------

set -e

# --- Configuration ---
PLUGIN_VERSION="2.2.1.1248"
PLUGIN_RELEASE="cxx-2.2.1"
PLUGIN_JAR="sonar-cxx-plugin-${PLUGIN_VERSION}.jar"
DOWNLOAD_URL="https://github.com/SonarOpenCommunity/sonar-cxx/releases/download/${PLUGIN_RELEASE}/${PLUGIN_JAR}"

CONTAINER_NAME="sonarqube"
CONTAINER_PLUGIN_DIR="/opt/sonarqube/extensions/plugins"

echo "Starting C++ Plugin Installation..."

# --- 1. Download Plugin to Host ---
echo "Downloading $PLUGIN_JAR..."
wget -q --show-progress "$DOWNLOAD_URL"

if [ ! -f "$PLUGIN_JAR" ]; then
    echo "ERROR: Download failed."
    exit 1
fi

# --- 2. Remove Old Versions ---
# We check if an older version exists in the container and remove it
# to prevent conflicts.
echo "Checking for existing C++ plugins..."
docker exec "$CONTAINER_NAME" \
    bash -c "rm -f $CONTAINER_PLUGIN_DIR/sonar-cxx-plugin-*.jar"

# --- 3. Install New Plugin ---
echo "Installing new plugin..."
docker cp "$PLUGIN_JAR" "$CONTAINER_NAME:$CONTAINER_PLUGIN_DIR/"

# --- 4. Fix Permissions ---
# The file copied from host might be owned by root.
# SonarQube runs as UID 1000.
echo "Fixing permissions..."
docker exec -u 0 "$CONTAINER_NAME" \
    chown 1000:1000 "$CONTAINER_PLUGIN_DIR/$PLUGIN_JAR"

# --- 5. Cleanup Host File ---
rm "$PLUGIN_JAR"

# --- 6. Restart SonarQube ---
echo "Restarting SonarQube to load plugin..."
docker restart "$CONTAINER_NAME"

echo "Plugin installed. Please verify in Administration > Marketplace > Installed."