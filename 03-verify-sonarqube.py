#!/usr/bin/env python3

import urllib.request
import urllib.error
import json
import time
import sys

# --- Configuration ---
# We verify from the perspective of the 'dev-container'
# using the internal Docker DNS name.
TARGET_URL = "http://sonarqube.cicd.local:9000/api/system/status"
MAX_RETRIES = 5
WAIT_SECONDS = 2

def verify_sonarqube():
    print(f"--- Starting SonarQube Verification ---")
    print(f"Target: {TARGET_URL}")

    for i in range(MAX_RETRIES):
        try:
            print(f"Attempt {i+1}/{MAX_RETRIES}...", end=" ", flush=True)

            # Make the request
            with urllib.request.urlopen(TARGET_URL) as response:
                if response.status != 200:
                    print(f"FAILED (HTTP {response.status})")
                    continue

                # Parse JSON
                data = json.loads(response.read().decode())
                status = data.get("status")

                print(f"CONNECTED")
                print(f"    System Status: {status}")

                if status == "UP":
                    print("✅ SUCCESS: SonarQube is fully operational.")
                    return True
                elif status == "STARTING":
                    print("⏳ WAITING: SonarQube is still initializing (Elasticsearch loading)...")
                elif status == "DB_MIGRATION_NEEDED":
                    print("⚠️  WARNING: Database migration required.")
                    return False
                else:
                    print(f"⚠️  Unknown Status: {status}")
                    return False

        except urllib.error.URLError as e:
            print(f"FAILED ({e.reason})")
            print("    (Check if 'sonarqube.cicd.local' resolves or if the container is running)")
        except Exception as e:
            print(f"ERROR: {e}")

        if i < MAX_RETRIES - 1:
            time.sleep(WAIT_SECONDS)

    print("❌ FAILURE: Could not verify SonarQube status after multiple attempts.")
    return False

if __name__ == "__main__":
    if not verify_sonarqube():
        sys.exit(1)