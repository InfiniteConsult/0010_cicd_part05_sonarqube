#!/usr/bin/env python3

import sys
import yaml
import os

# Target the LIVE configuration in the cicd_stack
JCAS_FILE = os.path.expanduser("~/cicd_stack/jenkins/config/jenkins.yaml")

def update_jcasc():
    print(f"[INFO] Reading JCasC file: {JCAS_FILE}")

    try:
        with open(JCAS_FILE, 'r') as f:
            jcasc = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {JCAS_FILE}")
        sys.exit(1)

    # 1. Add SonarQube Admin Token Credential
    print("[INFO] Injecting SonarQube Admin Token credential...")

    if 'credentials' not in jcasc:
        jcasc['credentials'] = {'system': {'domainCredentials': [{'credentials': []}]}}

    sonar_cred = {
        'string': {
            'id': 'sonar-admin-token',
            'scope': 'GLOBAL',
            'description': 'SonarQube Admin Token',
            'secret': '${SONAR_AUTH_TOKEN}'
        }
    }

    # Safe navigation to credentials list
    if 'system' not in jcasc['credentials']:
        jcasc['credentials']['system'] = {'domainCredentials': [{'credentials': []}]}

    domain_creds = jcasc['credentials']['system']['domainCredentials']
    if not domain_creds:
        domain_creds.append({'credentials': []})

    creds_list = domain_creds[0]['credentials']
    if creds_list is None:
        creds_list = []
        domain_creds[0]['credentials'] = creds_list

    # Idempotency Check
    exists = False
    for cred in creds_list:
        if 'string' in cred and cred['string'].get('id') == 'sonar-admin-token':
            exists = True
            break

    if not exists:
        creds_list.append(sonar_cred)
        print("[INFO] Credential 'sonar-admin-token' added.")
    else:
        print("[INFO] Credential 'sonar-admin-token' already exists. Skipping.")

    # 2. Add SonarQube Global Configuration
    print("[INFO] Injecting SonarQube Server configuration...")

    if 'unclassified' not in jcasc:
        jcasc['unclassified'] = {}

    # The 'sonarGlobalConfiguration' block configures the SonarScanner plugin
    jcasc['unclassified']['sonarGlobalConfiguration'] = {
        'buildWrapperEnabled': True,
        'installations': [{
            'name': 'SonarQube',
            'serverUrl': 'http://sonarqube.cicd.local:9000',
            'credentialsId': 'sonar-admin-token',
            'webhookSecretId': '' # Optional: We will configure webhooks later
        }]
    }

    # 3. Write back to file
    print("[INFO] Writing updated JCasC file...")
    with open(JCAS_FILE, 'w') as f:
        yaml.dump(jcasc, f, default_flow_style=False, sort_keys=False)

    print("[INFO] JCasC update complete.")

if __name__ == "__main__":
    update_jcasc()