# 1. Start from the official Community Edition
FROM sonarqube:community

# 2. Switch to root to perform system administration (Certificate Import)
USER root

# 3. Copy the Local CA from the build context (Current Directory)
COPY ca.pem /tmp/ca.pem

# 4. Import the CA into the JVM Truststore
#    We use the $JAVA_HOME environment variable provided by the base image.
#    The default password for the java truststore is 'changeit'.
RUN keytool -importcert \
    -file /tmp/ca.pem \
    -keystore "$JAVA_HOME/lib/security/cacerts" \
    -alias "CICD-Root-CA" \
    -storepass changeit \
    -noprompt \
    && rm /tmp/ca.pem

# 5. Switch back to the unprivileged sonarqube user
USER sonarqube