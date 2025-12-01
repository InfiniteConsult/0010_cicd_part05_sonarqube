# Chapter 1: The Challenge - Quantity vs. Quality

## 1.1 The "Green Build" Fallacy

In our previous session, we completed the construction of the **"Software Supply Chain."** We successfully integrated **GitLab** (The Library), **Jenkins** (The Factory), and **Artifactory** (The Warehouse) into a seamless, automated conduit. When a developer pushes code, our city springs to life: webhooks fire, agents are provisioned, code is compiled, and immutable artifacts are delivered to secure storage.

If you look at your Jenkins dashboard right now, you will likely see a column of green checks. The pipeline works. The artifacts are safe. The system is functioning exactly as designed.

But this "Green Build" is a lie.

We have built a system that prioritizes **Quantity over Quality**. Our factory is incredibly efficient at moving boxes, but it has absolutely no idea what is *inside* them. If a developer commits a C++ memory leak, a Python type error, or a Rust panic handler, our pipeline will happily compile it, package it, and ship it to the warehouse with a stamp of approval. We are effectively filling our secure bunker with "Time Bombs"—defective software that will only explode when it reaches production.

This reveals a critical "Blind Spot" in our architecture. We have established **Continuous Integration** (merging code) and **Continuous Delivery** (shipping code), but we have completely neglected **Continuous Inspection**. We have no way to measure the *health* of our codebase. We don't know if our test coverage is improving or degrading. We don't know if our cyclomatic complexity is spiraling out of control. We are flying blind, trusting that "if it compiles, it works."

In a high-assurance environment—like the one we are simulating—this is unacceptable. A build that compiles but introduces a critical security vulnerability is not a success; it is a containment breach. We need a mechanism to detect these flaws *before* the artifact is signed and sealed.

## 1.2 The "Quality Gate" Concept

To solve this, we must introduce a new entity to our city: the **"Inspector."**

Architecturally, this Inspector sits between the Factory (Jenkins) and the Warehouse (Artifactory). Its role is not to build code, but to analyze it. It must disassemble the "box" our factory produced, x-ray the contents, measure the tolerances, and verify that the product meets our engineering standards.

But inspection alone is passive. A report that says "Your code has 50 bugs" is useless if the pipeline has already shipped that code to the warehouse.

We need to implement a **Quality Gate**. This is a binary decision point in our pipeline. It transforms our "Inspector" from a passive observer into an active gatekeeper. The Inspector must have the authority to **"Stop the Line"** (the famous Toyota "Andon Cord" principle).

If the code coverage drops below 80%, the line stops. If a new security vulnerability is detected, the line stops. If the technical debt ratio exceeds 5%, the line stops.

When the line stops, the build fails. The artifact is rejected. It never reaches the Warehouse. This ensures that every single artifact in Artifactory is not just "built," but "certified."

## 1.3 The Solution: SonarQube Community Build

To fulfill this role, we will deploy **SonarQube**.

SonarQube is the industry standard for static code analysis. It provides a centralized dashboard that tracks code health over time, visualizing metrics like duplication, complexity, and test coverage.

However, we must navigate a specific constraint. We are deploying the **SonarQube Community Build** (specifically version 25.x). This free version is powerful, but it comes with architectural limitations that distinguish it from the paid Enterprise editions:

1.  **No Native C or C++ Analysis:** Out of the box, the Community Build ignores both C and C++ files entirely. Since our "Hero Project" is a true polyglot implementation—containing distinct, idiomatic C23 code *and* C++23 code—this is a major blocker. We will have to engineer a "First Principles" workaround using community plugins to "unlock" analysis for these compiled languages.
2.  **Branch Analysis Limitations:** It generally only analyzes the `main` branch, limiting our ability to decorate Pull Requests directly.

Despite these constraints, it is the perfect tool for our "Inspector." Our goal is to deploy it into our secure `cicd-net`, force it to trust our internal PKI, and integrate it with Jenkins to enforce a strict Quality Gate on our C, C++, Rust, and Python code.

# Chapter 2: Architecture - The Host & The Kernel

## 2.1 The Hidden Dependency: Elasticsearch & The Kernel

To understand why deploying SonarQube is fundamentally different from deploying Jenkins or GitLab, we must first deconstruct its internal architecture.

When you launch a Jenkins container, you are essentially launching a standard Java Web Archive (WAR) inside a Jetty web server. It is a monolithic, CPU-bound application. If you give it enough RAM, it runs.

SonarQube, however, is not a single application; it is a distributed system packaged into a single binary. When the container starts, a master Java process spawns three distinct child processes:
1.  **The Web Server:** Serves the UI and API.
2.  **The Compute Engine:** Processes the heavy analysis reports sent by scanners.
3.  **The Search Engine (Elasticsearch):** Indexes every line of code, every issue, and every metric for instant retrieval.

It is this third component—**Elasticsearch**—that introduces a critical "Abstraction Leak" in our Docker environment.

### The Mechanics of `mmapfs`
Elasticsearch is built on top of **Apache Lucene**, a high-performance search library. To achieve the incredible speed required to search through millions of lines of code in milliseconds, Lucene relies heavily on a file system feature called **Memory Mapped Files (`mmap`)**.

In a standard file read, the operating system copies data from the disk into a kernel buffer, and then copies it again into the application's memory. This "double copy" is slow.

With `mmap`, Lucene tells the Operating System to map the physical file on the disk directly into the process's virtual memory address space. The application can then read the file as if it were essentially a massive array in RAM. The OS handles the complexity of paging data in from the disk only when it is accessed. This eliminates the system call overhead and allows Elasticsearch to perform near-memory-speed searches on datasets that are larger than the available RAM.

### The Abstraction Leak
This architecture relies on the Operating System allowing a process to create thousands upon thousands of these memory maps—one for every index segment.

Here lies the conflict with Docker.

While Docker provides excellent isolation for the **Filesystem** (via UnionFS) and **Process Namespace** (PID), it shares the **Kernel** with the host machine. Kernel-level tunables, such as memory management limits, are enforced globally by the host kernel.

By default, most Linux distributions (including Debian 12) are tuned for desktop or standard server workloads. They conservatively limit the maximum number of memory map areas a process can have (`vm.max_map_count`) to approximately **65,530**.

For a web server, this is plenty. For Elasticsearch, it is suffocating. SonarQube requires a minimum of **262,144** (and recommends **524,288** for larger instances) to function correctly.

### The Failure Mode
If we attempt to run `sonarqube:community` on a standard Linux host without modification, we encounter a particularly frustrating failure mode:
1.  The container starts successfully (Docker sees no error).
2.  The SonarQube wrapper process launches.
3.  The Elasticsearch child process attempts to initialize its indices.
4.  The Host Kernel denies the `mmap` request because the limit (65,530) is exceeded.
5.  Elasticsearch crashes silently or throws a "bootstrap check failure."
6.  The SonarQube wrapper sees its child process die, shuts down the web server, and kills the container.

To the user, the container simply enters a "Restart Loop" with no obvious error message unless you dig deep into the specific `es.log` file inside the container volume. To build a stable "Inspector," we must proactively reconfigure the Host Kernel to support this workload.

## 2.2 The "Architect" Script (`01-setup-sonarqube.sh`)

To solve the "Abstraction Leak" described above, we cannot rely on Docker. We must intervene at the Host Operating System level.

We will assign this responsibility to our **"Architect"** script. Unlike previous setup scripts that primarily focused on generating configuration files or SSL certificates, this script acts as a **Host State Enforcer**. It must inspect the physical machine it is running on, determine if it is capable of supporting our workload, and apply the necessary kernel modifications if it finds the host lacking.

This requires a two-pronged strategy to ensure stability across time:

1.  **The Runtime Fix (`sysctl -w`):** This command writes directly to the kernel's parameters in memory (specifically `/proc/sys/vm/max_map_count`). This change takes effect instantly, allowing us to launch the container immediately without restarting the host machine. However, because it is in memory, it is volatile; it will vanish if the server reboots.
2.  **The Persistence Fix (`/etc/sysctl.conf`):** To survive a reboot, we must write the configuration to the system's control file. On boot, the OS reads this file and re-applies the settings.

A naive script might simply append the configuration to the end of the file. However, in a "First Principles" architecture, we aim for **idempotency**. If we run the script ten times, it should not add ten identical lines to the configuration file. Our script must be intelligent enough to parse the existing configuration, detect if the limit is already sufficient, and update it *in place* using `sed` only if necessary.

Create this file at `~/cicd_stack/sonarqube/01-setup-sonarqube.sh`.

```bash
#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               01-setup-sonarqube.sh
#
#  This is the "Architect" script for SonarQube.
#  It prepares the host environment.
#
#  WARNING: This script requires SUDO privileges to update
#           kernel parameters (vm.max_map_count) in /etc/sysctl.conf
#
#  1. Kernel Check: Enforces vm.max_map_count >= 524288
#     (Strict requirement for the embedded Elasticsearch).
#  2. Secrets: Verifies Database passwords exist in cicd.env.
#  3. Env: Generates the scoped 'sonarqube.env' for Docker.
#
# -----------------------------------------------------------

set -e

# --- 1. Define Paths ---
HOST_CICD_ROOT="$HOME/cicd_stack"
SONAR_BASE="$HOST_CICD_ROOT/sonarqube"
MASTER_ENV_FILE="$HOST_CICD_ROOT/cicd.env"
SCOPED_ENV_FILE="$SONAR_BASE/sonarqube.env"

echo "Starting SonarQube 'Architect' Setup..."

# --- 2. Kernel Prerequisites (Elasticsearch) ---
# SonarQube uses embedded Elasticsearch which requires high mmap counts.
# We must ensure the host allows this.

REQUIRED_MAX_MAP=524288
SYSCTL_CONF="/etc/sysctl.conf"

echo "--- Phase 1: Checking Kernel Parameters ---"

# A. Runtime Check (Immediate Fix)
# We read the current value from the kernel
CURRENT_RUNTIME_MAP=$(sysctl -n vm.max_map_count)

if [ "$CURRENT_RUNTIME_MAP" -lt "$REQUIRED_MAX_MAP" ]; then
    echo "Limit too low ($CURRENT_RUNTIME_MAP). Updating immediately..."
    # Apply the fix to the live kernel
    sudo sysctl -w vm.max_map_count=$REQUIRED_MAX_MAP
else
    echo "Runtime limit is sufficient ($CURRENT_RUNTIME_MAP)."
fi

# B. Persistence Check (sysctl.conf)
# We ensure the setting survives a reboot
echo "    Checking persistence in $SYSCTL_CONF..."

# Check if entry exists (handling optional leading whitespace)
if grep -q "^\s*vm.max_map_count" "$SYSCTL_CONF"; then
    # Value exists, extract it (handling spaces around '=')
    STORED_VAL=$(grep "^\s*vm.max_map_count" "$SYSCTL_CONF" | awk -F= '{print $2}' | tr -d '[:space:]')
    
    # Ensure we captured a number
    if [[ ! "$STORED_VAL" =~ ^[0-9]+$ ]]; then
        echo "Could not parse stored value. Appending correct config..."
        echo "vm.max_map_count=$REQUIRED_MAX_MAP" | sudo tee -a "$SYSCTL_CONF" > /dev/null
    elif [ "$STORED_VAL" -lt "$REQUIRED_MAX_MAP" ]; then
        echo "Stored value ($STORED_VAL) is too low. Updating config..."
        # Use regex to replace the line regardless of spacing
        sudo sed -i "s/^\s*vm.max_map_count.*/vm.max_map_count=$REQUIRED_MAX_MAP/" "$SYSCTL_CONF"
    else
        echo "Stored configuration is sufficient ($STORED_VAL)."
    fi
else
    # Value missing, append it
    echo "Value missing. Appending to config..."
    echo "vm.max_map_count=$REQUIRED_MAX_MAP" | sudo tee -a "$SYSCTL_CONF" > /dev/null
fi


# --- 3. Directory Setup ---
echo "--- Phase 2: Directory Scaffolding ---"
mkdir -p "$SONAR_BASE"

# --- 4. Secrets Validation ---
echo "--- Phase 3: Secrets Management ---"

if [ ! -f "$MASTER_ENV_FILE" ]; then
    echo "ERROR: Master env file not found at $MASTER_ENV_FILE"
    exit 1
fi

# Load Master Secrets
set -a
source "$MASTER_ENV_FILE"
set +a

# Verify Database Password exists (Created in Article 9)
if [ -z "$SONARQUBE_DB_PASSWORD" ]; then
    echo "ERROR: SONARQUBE_DB_PASSWORD not found in cicd.env"
    echo "   Please run the Database Setup (Article 9) first."
    exit 1
fi

# --- 5. Generate Scoped Environment File ---
echo "--- Phase 4: Generating 'sonarqube.env' ---"

# We map our master secrets to the specific env vars SonarQube expects.
# We also inject the IPv4 fix here to ensure stable internal Docker networking.

cat << EOF > "$SCOPED_ENV_FILE"
# Scoped Environment for SonarQube Container
# Auto-generated by 01-setup-sonarqube.sh

# Database Connection
# We use the internal Docker DNS name for Postgres
SONAR_JDBC_URL=jdbc:postgresql://postgres.cicd.local:5432/sonarqube
SONAR_JDBC_USERNAME=sonarqube
SONAR_JDBC_PASSWORD=$SONARQUBE_DB_PASSWORD

# Network / JVM Fixes
# Forces the JVM to use IPv4 to prevent connection issues within the container
# (e.g. timeout connecting to localhost)
SONAR_WEB_JAVAADDITIONALOPTS=-Djava.net.preferIPv4Stack=true
EOF

# Secure the file
chmod 600 "$SCOPED_ENV_FILE"

echo "Setup complete."
echo "   Kernel configured."
echo "   Secrets injected into $SCOPED_ENV_FILE"
echo "   Ready to run 02-build-image.sh"
```

### Deconstructing the Architect

**1. The Host Surgery (Phase 1)**
This section breaks the "Container Isolation" rule out of necessity. We use `sudo` not to manage Docker, but to manage the Linux Kernel. The script is defensive: it checks `grep "^\s*vm.max_map_count"` with a regex that tolerates leading whitespace, ensuring that if a human administrator manually indented the config file, our script won't blindly append a duplicate entry.

**2. The Dependency Guard (Phase 3)**
We explicitly check for `SONARQUBE_DB_PASSWORD`. This reinforces the dependency chain we built in **Article 9**. We are *not* creating a database here. We are assuming the centralized "Water Treatment Plant" (PostgreSQL) is operational. If the password isn't in the environment file, the script fails fast, preventing us from launching a container that would immediately crash on a connection error.

**3. The IPv4 Mandate (Phase 4)**
In the generated environment file, we inject `SONAR_WEB_JAVAADDITIONALOPTS=-Djava.net.preferIPv4Stack=true`. This is a critical stability fix for Java applications running inside Docker. By default, the JVM may attempt to bind to IPv6 addresses (`::1`), while Docker's internal networking often routes exclusively via IPv4. This mismatch can cause inter-process communication (IPC) between the SonarQube Web Server and Compute Engine to time out, leading to a "zombie" state where the UI never loads. This flag forces the JVM to speak the language of the container network.

## 2.3 Secrets & The "Scoped Environment"

With the host operating system prepared, we turn our attention to the container's configuration. In previous articles, such as Jenkins and Artifactory, we relied heavily on bind-mounting configuration files (`jenkins.yaml` or `system.yaml`) from the host into the container.

For SonarQube, we are changing tactics. We will adopt the **Twelve-Factor App** methodology, which mandates storing configuration in the **Environment**, not in files.

While SonarQube *does* support a `sonar.properties` file, modifying it inside a Docker deployment is an anti-pattern. It requires either:
1.  **Bind-mounting the file:** This overrides the default configuration inside the image, forcing us to maintain a complex file on the host that might drift from the container's internal defaults during an upgrade.
2.  **Building a custom image:** copying a static file into the image creates a hard-coded secret risk.

Instead, the official SonarQube Docker image is designed to read specific environment variables and inject them into its internal configuration at runtime. Our "Architect" script acts as a bridge, translating our master secrets into these specific variables.

We generate a **Scoped Environment File** (`sonarqube.env`). This file serves a specific security purpose: **Least Privilege**. We do not pass our entire `cicd.env` (which contains GitLab tokens, Jenkins secrets, and Root CA passwords) to the SonarQube container. We generate a file containing *only* the three variables it needs to access the database:

* **`SONAR_JDBC_URL`**: We point this to `jdbc:postgresql://postgres.cicd.local:5432/sonarqube`. Note that we use the internal DNS name established in Article 5.
* **`SONAR_JDBC_USERNAME`**: `sonarqube`.
* **`SONAR_JDBC_PASSWORD`**: The high-entropy string we generated in Article 9.

This approach keeps our container's environment clean and audit-friendly.

## 2.4 The Dependency Chain

Finally, our architecture enforces a strict **Dependency Chain**.

In a novice setup, a `docker-compose.yml` file might attempt to spin up a database and the application simultaneously. This often leads to race conditions where the application crashes because the database is not yet ready to accept connections.

In our "City Planning" model, we treat the database as **Public Utility Infrastructure**. We established the PostgreSQL service in **Article 9**. It is a permanent fixture of our city, running independently of the applications that consume it.

Our `01-setup-sonarqube.sh` script enforces this relationship. Before it writes a single configuration line, it checks for the existence of `SONARQUBE_DB_PASSWORD` in the master environment file.

* **If the variable is missing:** It means the database infrastructure has not been provisioned. The script fails fast with a clear error: `Please run the Database Setup (Article 9) first.`
* **If the variable exists:** It assumes the utility is online and proceeds to provision the application.

This logic prevents "Orphaned Services"—applications deployed without a backend—and ensures that our infrastructure is built in the correct, layered order: **Network $\rightarrow$ Storage $\rightarrow$ Database $\rightarrow$ Application.**

# Chapter 3: The Trust Gap - A Familiar Foe

## 3.1 The Connectivity Paradox (and a Confession)

In our initial attempt to deploy this service, we fell into a trap. We launched the official `sonarqube:community` image, updated our host's `/etc/hosts` file to resolve `sonarqube.cicd.local` to `127.0.0.1`, and successfully accessed the UI on port 9000. The dashboard loaded, the database connected, and the logs were clean. We felt victorious.

Then, we tried to configure the **GitLab** integration. We entered our GitLab URL (`https://gitlab.cicd.local:10300/api/v4`) and clicked "Save."

The result was an immediate crash: `PKIX path building failed`.

We must make a confession: even after ten articles of preaching "First Principles," we got lulled into a false sense of security by the **Community Build's** primary limitation. Because this version of SonarQube does not support *inbound* HTTPS (forcing us to run it as an HTTP service), we mentally categorized it as an "insecure" service.

This was a mistake. While SonarQube listens on HTTP, it acts as a **Client** to other services in our city. To import projects, it must talk to GitLab. To authenticate users, it might need to talk to LDAP. To send webhooks, it must talk to Jenkins.

All of these internal services are secured by our **Local Root CA**. The official SonarQube container, running a standard OpenJDK runtime, has no knowledge of this CA. It is an island. When it attempts to handshake with GitLab, it sees an unknown certificate issuer and terminates the connection to protect itself.

We cannot simply "turn off SSL verification" in SonarQube without compromising the integrity of our entire architecture. We must fix the root of trust.

## 3.2 The "Builder" Pattern (Revisited)

We faced this exact problem with the **Jenkins Controller** in Article 8. The solution remains the same.

We reject the "quick fix" of bind-mounting the host's `/etc/ssl/certs/java/cacerts` file into the container. This is fragile; if the container's Java version (e.g., Java 17) differs from the host's Java version (e.g., Java 11), the binary keystore format may be incompatible, leading to cryptic startup failures.

Instead, we will apply the **Builder Pattern**. We will create a `Dockerfile` that extends the official image, briefly switches to the `root` user, and uses the native Java `keytool` utility to "bake" our "Passport Office" license (`ca.pem`) directly into the container's immutable system trust store.

This ensures that any container spawned from this image carries our trust relationships with it, making it a first-class citizen of our secure city.

## 3.3 The Implementation (`02-build-image.sh`)

To execute this, we need two files: the `Dockerfile` blueprint and a builder script to orchestrate the context.

There is a specific nuance here regarding **User Context**. SonarQube runs as a non-privileged user (`sonarqube`, UID 1000). However, modifying the system-wide Java keystore requires root privileges. Our Dockerfile must explicitly handle this privilege escalation and then de-escalate back to the correct user to ensure runtime permissions match our volume mounts.

Create the **`Dockerfile`** in `~/cicd_stack/sonarqube/`:

```dockerfile
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
```

Now, create the builder script, **`02-build-image.sh`**. This script handles the "Build Context" trap we encountered in previous articles by copying the CA certificate into the current directory before building.

```bash
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

echo "🚀 Starting SonarQube Custom Build..."

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

echo "✅ Build complete."
echo "   Image: sonarqube-custom:latest"
echo "   Ready to run 03-deploy-sonarqube.sh"
```

# Chapter 4: Deployment - Launching the Inspector

## 4.1 The "Launcher" Script (`03-deploy-sonarqube.sh`)

With our host kernel tuned by the "Architect" and our trust store baked by the "Builder," we are finally ready to execute the deployment.

We will use our standard **"Launcher"** pattern. This script is not just a wrapper for `docker run`; it is an enforcement mechanism for our infrastructure's state. It ensures that every deployment begins with a "Clean Slate," preventing the configuration drift that plagues manual server management.

For SonarQube specifically, this script has an additional responsibility: **Persistence Management**. Unlike Jenkins, which can technically survive with a single volume, SonarQube requires a strict separation of concerns for its storage to survive upgrades and plugin installations. We must verify that three distinct "Storage Lockers" (Named Volumes) exist before the application starts.

Create this file at `~/cicd_stack/sonarqube/03-deploy-sonarqube.sh`.

```bash
#!/usr/bin/env bash

#
# -----------------------------------------------------------
#               03-deploy-sonarqube.sh
#
#  This is the "Launcher" script for SonarQube.
#  It performs a clean-slate deployment of the container.
#
#  1. Clean Slate: Stops/Removes existing container.
#  2. Volumes: Ensures data, extensions, and logs volumes exist.
#  3. Launch: Runs sonarqube-custom:latest with strict networking.
#
# -----------------------------------------------------------

set -e

# --- 1. Define Paths ---
HOST_CICD_ROOT="$HOME/cicd_stack"
SONAR_BASE="$HOST_CICD_ROOT/sonarqube"
# We use the scoped environment file generated by the Architect script
SCOPED_ENV_FILE="$SONAR_BASE/sonarqube.env"

echo "Starting SonarQube Deployment..."

# --- 2. Prerequisite Checks ---
if [ ! -f "$SCOPED_ENV_FILE" ]; then
    echo "ERROR: Scoped env file not found at $SCOPED_ENV_FILE"
    echo "Please run 01-setup-sonarqube.sh first."
    exit 1
fi

# --- 3. Clean Slate Protocol ---
# We destroy the container to ensure configuration changes (env vars, mounts)
# are applied fresh. We never just 'restart' a stale container.
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
# - data: The heavy Elasticsearch indices and embedded DB (if used)
# - extensions: Plugins (like sonar-cxx)
# - logs: Critical for debugging Elasticsearch startup failures

echo "Verifying Docker volumes..."
docker volume create sonarqube-data > /dev/null
docker volume create sonarqube-extensions > /dev/null
docker volume create sonarqube-logs > /dev/null
echo "Volumes verified."

# --- 5. Deploy Container ---
echo "Launching SonarQube (Custom Image)..."

# Notes on Configuration:
# - Image: We use 'sonarqube-custom:latest' (built in Step 02)
#          to ensure the JVM trusts our Local CA.
# - Net:   We connect to 'cicd-net' so we can reach Postgres/GitLab.
# - Port:  We bind STRICTLY to 127.0.0.1 to prevent external access.

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
  sonarqube-custom:latest

echo "SonarQube container started."
echo "   It will take 2-3 minutes to initialize Elasticsearch."
echo "   Monitor logs with: docker logs -f sonarqube"
echo ""
echo "   Wait for: 'SonarQube is operational'"
echo "   Then access: http://sonarqube.cicd.local:9000"
echo "   (Don't forget to add '127.0.0.1 sonarqube.cicd.local' to your /etc/hosts file)"
```

### Deconstructing the Launcher

**1. The Persistence Trinity (Volume Management)**
We explicitly provision three volumes. While `data` and `extensions` are standard, the **`sonarqube-logs`** volume is often overlooked in beginner tutorials. This is a mistake.
SonarQube's startup sequence is complex. If the Elasticsearch engine fails (due to memory limits or corruption), the container will die immediately. If you do not persist the logs, the error message vanishes with the container. By mounting `/opt/sonarqube/logs`, we ensure that we can perform forensics on a crashed container even after it has been removed.

**2. The Configuration Injection (`--env-file`)**
We inject the `sonarqube.env` file we generated in Chapter 2. This keeps our `docker run` command clean and audit-safe. It ensures that the database credentials and the critical `SONAR_WEB_JAVAADDITIONALOPTS` flag are present in the runtime environment.

**3. The Custom Image (`sonarqube-custom:latest`)**
Critically, we do **not** run `sonarqube:community`. We run the custom image we built in Chapter 3. This is the difference between a working system and a broken one. If we reverted to the official image here, our database connection would work, but our GitLab integration would silently fail with SSL handshake errors later. We strictly enforce the use of our "Trusted" image.

## 4.2 Network Security & The "Localhost Binding"

In our `docker run` command, you might have noticed a specific nuance in the port mapping flag: `--publish 127.0.0.1:9000:9000`.

This is not a stylistic choice; it is a critical security control necessitated by the architecture of the **SonarQube Community Build**.

Unlike GitLab (which bundles Nginx) or Jenkins (which runs on Jetty and supports native keystores), the Community Build of SonarQube has a hard architectural constraint: **it does not support inbound HTTPS.** The application server (Tomcat) is configured to speak only plain text HTTP.

In a traditional "Happy Path" tutorial, you might see instructions to map ports like `-p 9000:9000`. This is dangerous. When you omit the IP address, Docker binds the port to `0.0.0.0`—all network interfaces. This means your unencrypted SonarQube instance, carrying sensitive code metrics and potentially authentication tokens, would be instantly accessible to anyone on your local Wi-Fi network or corporate LAN.

We reject this exposure. By explicitly prepending `127.0.0.1`, we force Docker to bind the port **only** to the host's loopback interface.

This creates a "Poor Man's Firewall."
1.  **The Host:** You can access the UI via `localhost:9000` (or `sonarqube.cicd.local` via your hosts file) because you are on the machine.
2.  **The City:** Jenkins and GitLab can access it because they share the private `cicd-net` bridge network.
3.  **The World:** Anyone else on your network sees a closed port.

This mimics the "Air Gapped" architecture of high-security environments where internal tools are never exposed directly to the user network without an intervening Reverse Proxy or VPN.

## 4.3 The "Zombie State" Smoke Test (`04-verify-sonarqube.py`)

Launching the container is not the same as starting the service. Because SonarQube is a distributed system (Web + Compute + Search), it has a complex startup sequence that can take several minutes.

During this initialization phase, the Web Server port (9000) might accept TCP connections, but the application is not ready. It enters a "Zombie State" where it serves a "Maintenance Mode" page or simply hangs while waiting for Elasticsearch to index the database.

If we try to script against it too early, our automation will fail. A simple `curl` or `nc -z` check is insufficient because it only checks the TCP layer, not the Application layer.

We need a "Smoke Test" that verifies the **System Status**, ensuring that all three internal engines are green. We will write a Python script to poll the `api/system/status` endpoint from *inside* our control center.

Create this file at `~/Documents/FromFirstPrinciples/articles/0010_cicd_part06_sonarqube/04-verify-sonarqube.py`.

```python
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
MAX_RETRIES = 20
WAIT_SECONDS = 5

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
```

### Deconstructing the Smoke Test

**1. The Target (`sonarqube.cicd.local`)**
We run this script from the `dev-container`. It uses the internal Docker DNS name. This validates that our `cicd-net` is functioning and that the container is reachable on its internal port 9000.

**2. The Logic (`api/system/status`)**
We do not scrape HTML. We hit the official status API.

* **`STARTING`**: The web server is up, but Elasticsearch is still loading indices from disk. The script knows to wait and retry.
* **`UP`**: All child processes are healthy, and the database is connected. Only *now* is the system ready for login.

**3. Zero Dependencies**
We intentionally use Python's built-in `urllib` instead of `requests`. This ensures the script runs immediately inside our `dev-container` (or any minimal Python environment) without requiring a `pip install` step.

To run this verification:

1.  Enter your control center: `./dev-container.sh`
2.  Run the script: `python3 articles/0010_cicd_part06_sonarqube/04-verify-sonarqube.py`

## 4.4 Verification: The "First Login"

Once the smoke test returns `✅ SUCCESS`, we know the application is physically running. However, we must now verify that it is accessible from our **Host Machine** in a way that respects our networking architecture.

In **Article 7**, we established a pattern of using "Split-Horizon DNS" via the `/etc/hosts` file. We mapped `gitlab.cicd.local` to `127.0.0.1` so our browser would send the correct `Host` header, preventing CORS issues and redirection loops. We must apply the same rigor here.

Although we *could* access the server via `http://localhost:9000`, doing so creates an inconsistency between how *we* see the server and how *Jenkins* sees the server (as `sonarqube.cicd.local`). To align these perspectives, we update our host's DNS resolution.

**1. Update Hosts File (Host Machine):**

```bash
sudo nano /etc/hosts
# Add the following line (or append to existing):
127.0.0.1   sonarqube.cicd.local
```

**2. Access the UI:**
Open your web browser to **`http://sonarqube.cicd.local:9000`**.

You should be greeted by the login screen. Because we are running the Community Build, you will notice the connection is **Not Secure** (HTTP). This is expected and acceptable *only* because we explicitly bound the port to `127.0.0.1` in our Launcher script. We are connecting over the loopback interface, which is considered a trusted path in our "Air Gapped" simulation.

**3. The Credential Handshake:**
Log in with the factory default credentials:

* **Login:** `admin`
* **Password:** `admin`

Upon the first successful authentication, SonarQube will force you to update the password. Choose a strong password.

**Critical Step: Record the Secret**
Since we did not generate this password programmatically, it is not currently stored in our secrets file. To prevent locking yourself out of your own city, manually add this new password to your master environment file now.

Edit `~/cicd_stack/cicd.env` and add:

```bash
SONARQUBE_ADMIN_PASSWORD="<your_new_password>"
```

If you see the empty "Projects" dashboard, the deployment is a success. We have a running Inspector, backed by a tuned kernel, secure persistence, and a trusted communication channel. Now, we must connect it to the rest of the city.

# Chapter 5: The Bridge - Bidirectional Identity

## 5.1 The "Handshake" Protocol

We have a running Factory (Jenkins) and a running Inspector (SonarQube). They share the same network (`cicd-net`) and the same trust root (Local CA), but they are currently strangers. To establish a functioning Quality Gate, we must build a bridge between them.

This bridge is not a simple, one-way road. It is a **bidirectional handshake** necessitated by the asynchronous architecture of static analysis.

When a build runs, the interaction happens in two distinct phases:

1.  **The Outbound Push (Jenkins $\rightarrow$ SonarQube):**
    The Jenkins Agent runs the `sonar-scanner`. This tool scans the code, packages the raw data, and uploads it to the SonarQube server. To do this securely, the "Factory" needs a key to the "Inspector's" office. We cannot use a username and password here; we need a revocable, scoped **User Token**.

2.  **The Asynchronous Gap:**
    Once the scanner uploads the report, its job is done. It disconnects. However, the analysis is *not* complete. The SonarQube **Compute Engine** takes over, processing the report in the background. This can take anywhere from a few seconds to several minutes depending on the project size.
    During this gap, Jenkins is blind. It doesn't know if the project passed or failed.

3.  **The Inbound Callback (SonarQube $\rightarrow$ Jenkins):**
    When the Compute Engine finishes, it calculates the Quality Gate status (Green or Red). It must then pick up the "Red Phone" and call the Factory back to report the result. This requires a **Webhook**. SonarQube becomes the client, sending an HTTPS POST request to Jenkins to wake up the paused pipeline.

We must configure both sides of this relationship. If we miss the Token, the scan fails. If we miss the Webhook, the pipeline hangs forever, waiting for a call that never comes.

## 5.2 Identity Creation (UI & Secrets)

We begin by creating the credentials for the **Outbound** connection. Jenkins needs a key to access the SonarQube API.

In a fully mature "Configuration as Code" setup, we might provision this using a bootstrap script against the SonarQube API. However, because this is the "First Run" of our Inspector, we face a bootstrapping paradox: we need an admin token to use the API to create tokens. To resolve this, we will perform this specific setup manually in the UI, treating it as a one-time "City Key" generation event.

**1. Generate the Jenkins Token (SonarQube UI):**
Log in to SonarQube as `admin`. Navigate to **User Profile** (top right) \> **My Account** \> **Security**.
Generate a new token with the following attributes:

* **Name:** `jenkins-admin-token`
* **Type:** **User Token**. We choose this over a "Project Analysis Token" because Jenkins acts as a global orchestrator. It needs permissions to create projects, trigger scans, and configure webhooks across the entire system.
* **Expiration:** For this lab, "No expiration." In a real enterprise environment, you would establish a rotation policy here.

**2. Secure the Token (Host):**
Copy the token immediately. We must now persist this secret in our "Control Center" so our automation scripts can access it.
Open your master secrets file `~/cicd_stack/cicd.env` and add the token:

```bash
SONAR_ADMIN_TOKEN="<paste_your_token_here>"
```

**3. Configure the Library Link (GitLab ALM):**
While we are in the UI, we must also introduce the Inspector to the Library. This allows SonarQube to decorate Pull Requests and import repositories.
Navigate to **Administration** \> **Configuration** \> **General Settings** \> **DevOps Platform Integrations** \> **GitLab**.

* **Configuration Name:** `gitlab-cicd`
* **GitLab API URL:** `https://gitlab.cicd.local:10300/api/v4`
* **Personal Access Token:** Use the `GITLAB_API_TOKEN` you generated in Article 7.

Note the URL. We are using the internal **HTTPS** address. This connection will only succeed because we built our Custom Image in Chapter 3. If we were using the vanilla image, saving this configuration would trigger a certificate error.

## 5.3 The "Configuration Helper" (`update_jcasc_sonar.py`)

With the credentials secured, we face the integration challenge on the Jenkins side. We need to configure the **SonarQube Scanner** plugin.

In a manual setup, you would click through "Manage Jenkins" menus. In our "Configuration as Code" (JCasC) architecture, we must define this in `jenkins.yaml`.

However, the JCasC schema for plugins is notoriously brittle. The documentation is often sparse, and incorrect indentation or nesting will cause Jenkins to crash on boot. To solve this safely, we use our **Python Helper** pattern. Instead of using `sed` or `cat` to hack text into the YAML file, we treat the configuration as a structured data object.

We write a script that:

1.  **Parses** the existing `jenkins.yaml`.
2.  **Injects** the `sonar-admin-token` credential into the global credentials block.
3.  **Injects** the `sonarGlobalConfiguration` block under the `unclassified` root key.
4.  **Writes** the valid YAML back to disk.

Create this file at `~/cicd_stack/jenkins/config/update_jcasc_sonar.py`.

```python
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
```

### Deconstructing the Helper

* **`credentialsId: 'sonar-admin-token'`**: This links the server configuration to the credential we just injected.
* **`serverUrl: 'http://sonarqube.cicd.local:9000'`**: We use the internal Docker DNS name. Note that we use **HTTP** here, because we deliberately bound SonarQube to port 9000 without an SSL proxy for simplicity. Jenkins communicates over the private bridge network, so this traffic is isolated from the physical LAN.
* **`${SONAR_AUTH_TOKEN}`**: We do not hardcode the token in the YAML. We use a variable placeholder, which Jenkins will resolve at runtime from its environment variables. This is the next step in our integration.

## 5.4 The "Integrator" Script (`05-update-jenkins.sh`)

We now have the configuration helper logic defined, but we need a mechanism to execute it safely. We cannot simply run the Python script and hope for the best; we must ensure the environment variables it references (`${SONAR_AUTH_TOKEN}`) actually exist in the container's runtime.

This requires an orchestration script that bridges the gap between our Host credentials and the Container's environment.

Create this file at `~/cicd_stack/sonarqube/05-update-jenkins.sh`.

```bash
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
```

### Deconstructing the Integrator

**1. The Token Handshake (Step 1)**
This section solves the secret management problem. We read the `SONAR_ADMIN_TOKEN` from our master `cicd.env` file (where we manually saved it) and inject it into the specific `jenkins.env` file that the Jenkins container consumes. Note the variable renaming: we map `SONAR_ADMIN_TOKEN` (Host Name) to `SONAR_AUTH_TOKEN` (Container Name). This matches the `${SONAR_AUTH_TOKEN}` placeholder we wrote in our JCasC file.

**2. The Directory Context Switch (Step 3)**
This is a subtle but critical piece of shell scripting. The Jenkins deployment script (`03-deploy-controller.sh`) expects to be run from its own directory (because it references relative paths like `Dockerfile`). We use a subshell `(cd ... && ./...)` to temporarily switch contexts, execute the deployment logic we wrote in **Article 8**, and return. This allows us to trigger a rebuild of the "Factory" from the "Inspector's" directory, maintaining loose coupling between our modules.

**3. The "Re-Deploy" Philosophy**
We do not use `docker restart`. Simply restarting a container does *not* reload environment variables from the host file. By triggering the full deployment script (which performs `docker stop` / `docker rm` / `docker run`), we force Docker to read the updated `jenkins.env` file and inject the new token into the fresh container instance.

## 5.5 The Return Path (Webhook Setup)

We have successfully handed the "Foreman" (Jenkins) the keys to the "Inspector's" office. Jenkins can now authenticate with SonarQube and upload analysis reports.

However, the conversation is currently one-sided. When SonarQube finishes analyzing a report—a process that can take minutes for a large codebase—it has no way to tell Jenkins the result. Without this return signal, our pipeline’s `waitForQualityGate` step will simply hang until it times out, failing the build regardless of the code quality.

We must configure the **Inbound** connection: the **Webhook**.

Because this is a configuration setting inside the SonarQube application (application logic), not the server infrastructure, we must configure it via the UI (or API). We cannot configure this using Jenkins JCasC.

**Action: Configure the Webhook (SonarQube UI)**

1.  Log in to SonarQube (`http://sonarqube.cicd.local:9000`) as `admin`.
2.  Navigate to **Administration** > **Configuration** > **Webhooks**.
3.  Click the **Create** button.
4.  **Name:** Enter `jenkins-webhook`.
5.  **URL:** Enter `https://jenkins.cicd.local:10400/sonarqube-webhook/`.

**Critical Architectural Details:**
* **The Protocol (`https://`):** We are strictly using HTTPS. Jenkins is configured to reject insecure HTTP connections on its primary port. This connection is only possible because we built our **Custom SonarQube Image** in Chapter 3. If we were using the vanilla image, SonarQube would reject Jenkins' SSL certificate, and the webhook would fail silently.
* **The Address (`jenkins.cicd.local`):** We are using the internal Docker DNS name. This traffic never leaves our `cicd-net` bridge network; it travels directly from container to container, completely isolated from the host network.
* **The Endpoint (`/sonarqube-webhook/`):** This specific endpoint is exposed by the **SonarQube Scanner for Jenkins** plugin we installed in Article 8. It listens specifically for the JSON payload that SonarQube sends when a background task completes.

Click **Create**. The bridge is now complete. Traffic can flow from Factory to Inspector and back again. We are ready to test the flow.

# Chapter 6: The Toolchain Crisis - When Versions Collide

## 6.1 The Incident (The "Green Build" Breaks)

With our connectivity established and our project created in SonarQube, we were ready to attempt our first full "Quality Gate" build. We needed to transform our pipeline from a simple builder into an analytical engine.

To do this, we first had to adapt our coverage generation logic. Our existing `run-coverage.sh` was designed for humans, generating graphical HTML reports. SonarQube, however, is a machine; it requires structured data formats like **LCOV** (for C/C++ and Rust) and **Cobertura XML** (for Python).

We created a dedicated CI script, `run-coverage-cicd.sh`, to generate these specific artifacts.

```bash
#!/usr/bin/env bash
# run-coverage-cicd.sh

set -e

# --- 1. C/C++ Coverage (LCOV) ---
echo "--- Running C/C++ Tests & Coverage ---"
(
    mkdir -p build_debug
    cd build_debug || exit

    # Ensure Debug build for coverage flags
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    cmake --build . -- -j$(nproc)

    # Reset counters
    lcov --directory . --zerocounters

    # Run Tests
    ctest --output-on-failure

    # Capture Coverage
    lcov --capture \
         --directory . \
         --output-file coverage.info

    # Filter Artifacts
    lcov --remove coverage.info \
         '/usr/*' \
         '*/_deps/*' \
         '*/tests/helpers.h' \
         '*/benchmark/*' \
         '*/apps/*' \
         '*/docs/*' \
         '*/cmake/*' \
         '*/.cache/*' \
         -o coverage.filtered.info

    # Move to root for scanner pickup
    mv coverage.filtered.info ../coverage.cxx.info
)

# ... (Rust and Python sections omitted for brevity) ...
```

Next, we updated our `Jenkinsfile`. We replaced the old coverage script with our new CI-specific version and added the **Code Analysis** stage. Crucially, we wrapped the scanner in the `withSonarQubeEnv` block to inject our credentials and added the `waitForQualityGate` step to enforce the "Stop the Line" logic.

```groovy
        stage('Test & Coverage') {
            steps {
                echo '--- Running Tests & Generating Reports ---'
                sh 'chmod +x ./run-coverage-cicd.sh'
                sh './run-coverage-cicd.sh'
            }
        }

        stage('Code Analysis') {
            steps {
                // Inject SONAR_HOST_URL and SONAR_AUTH_TOKEN
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner'
                }
                
                // Pause pipeline and wait for the Quality Gate webhook
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
```

We pushed this configuration to GitLab, expecting the pipeline to turn green and populate our SonarQube dashboard with rich metrics.

Instead, the build crashed.

## 6.2 Forensics: CMake vs. LCOV

The Jenkins console output painted a very clear, albeit cryptic, picture of the disaster. Hidden among the standard build noise was this fatal error message:

```text
lcov: ERROR: (version) Incompatible GCC/GCOV version found while processing ...
    Your test was built with 'B42*'.
    You are trying to capture with gcov tool '/usr/local/bin/gcov' which is version 'B52*'.
```

To a systems programmer, this message is a "smoking gun." The GCOV data format is tightly coupled to the compiler version. The codes **`B42`** and **`B52`** are internal version identifiers for the GCOV format:

* **`B42` corresponds to GCC 12.** This is the default system compiler shipped with Debian 12.
* **`B52` corresponds to GCC 15.** This is the bleeding-edge compiler we manually compiled and installed in **Article 8**.

This error revealed a critical **"Split-Brain"** condition in our Factory Worker.

When the pipeline ran, two different tools made two different decisions about which compiler to use, resulting in a binary incompatibility:

1.  **The Builder (CMake):** When we ran `cmake ..`, it scanned the system for a C++ compiler. Because we had not explicitly told it otherwise, it looked for the standard `/usr/bin/c++` executable. On Debian, this is a symlink to the system's default **GCC 12**. It built our binaries using the old compiler.
2.  **The Inspector (LCOV):** When we ran `lcov`, it needed to use the `gcov` utility to read the coverage files. It searched the system `PATH`. Because we had added `/usr/local/bin` to the start of the `PATH` in our Dockerfile, it found our custom **GCC 15** `gcov` executable first.

The result was a pipeline that built code with one version (v12) and tried to analyze it with another (v15). Since the binary format for coverage artifacts (`.gcno`) changes between major GCC versions, the analyzer crashed immediately.

We had spent hours compiling a custom toolchain to avoid "it works on my machine" issues, yet our automated agent had silently drifted back to system defaults for compilation. To fix this, we had to understand *why* the agent behaved differently than our `dev-container`, where this setup worked perfectly.

## 6.3 The "Drift": Interactive vs. Non-Interactive Shells

The key to this mystery lay in a subtle distinction between how we use Docker as humans versus how Jenkins uses it as a machine.

When we, as developers, log into our `dev-container`, we typically start a `bash` shell. This is an **Interactive Shell**. When it starts, it reads configuration files like `~/.bashrc` to set up the user's environment. In **Article 1**, we added lines to `.bashrc` to export `CC=/usr/local/bin/gcc` and `CXX=/usr/local/bin/g++`. This ensured that whenever we typed `cmake`, our custom compiler was active.

Jenkins, however, does not log in like a human. When the Jenkins Agent connects to the controller and executes a pipeline step (`sh './run-coverage-cicd.sh'`), it runs a **Non-Interactive, Non-Login Shell**.

In this mode, **`.bashrc` is ignored**.

Because the environment variables were defined only in a user configuration file and not at the system level, the Jenkins agent reverted to the default behavior. It ignored our custom compiler settings, found the system default `/usr/bin/c++`, and built the project with GCC 12. Meanwhile, our `lcov` tool—installed globally in `/usr/local/bin`—remained at version 15.

This "Environmental Drift" is a classic failure mode in CI/CD. It highlights why relying on user-level dotfiles (`.bashrc`, `.profile`) is dangerous for automation. To fix this, we must move our configuration from the "User Layer" to the "Image Layer."

## 6.4 The Fix: Immutable Environment Variables

To solve this permanently, we must bake our toolchain selection directly into the Docker image metadata, ensuring it applies to *every* process, regardless of how it is spawned.

We will return to **Article 8** and patch our `Dockerfile.agent`. We will use the `ENV` instruction to set the `CC`, `CXX`, and `LD_LIBRARY_PATH` variables. Unlike `RUN export ...`, which only affects the current build step, `ENV` variables persist in the final image.

We will inject these instructions *after* our heavy compilation steps (GCC and Python) but *before* the final setup. This preserves our Docker build cache, saving us from recompiling GCC 15 (which takes \~30 minutes).

**File Location:** `~/Documents/FromFirstPrinciples/articles/0008_cicd_part04_jenkins/Dockerfile.agent`

Insert this block after the Python build loop:

```dockerfile
# ... (End of Step 8: Build Python) ...

# 8.5. Force CMake to use the custom GCC
# We update .bashrc for interactive shells and set ENV for CI pipelines.
RUN echo "export CC=/usr/local/bin/gcc" >> /root/.bashrc \
    && echo "export CXX=/usr/local/bin/g++" >> /root/.bashrc \
    && echo "export CC=/usr/local/bin/gcc" >> /home/jenkins/.bashrc \
    && echo "export CXX=/usr/local/bin/g++" >> /home/jenkins/.bashrc

ENV CC="/usr/local/bin/gcc"
ENV CXX="/usr/local/bin/g++"
ENV LD_LIBRARY_PATH="/usr/local/lib64:${LD_LIBRARY_PATH}"

# ... (Start of Step 9: Install SonarScanner) ...
```

## 6.5 Verification

With the patch applied, we must rebuild the agent image.

1.  **Rebuild:** Run the builder script from **Article 8**:

    ```bash
    cd ~/Documents/FromFirstPrinciples/articles/0008_cicd_part04_jenkins
    ./02-build-images.sh
    ```

    Because we inserted the new instructions *after* the heavy compilation steps, Docker will use cached layers for GCC and Python. The rebuild should take seconds, not minutes.

2.  **Retest:** Trigger the `0004_std_lib_http_client` job in Jenkins again.

**The Result:**
The `Incompatible GCC/GCOV version` error vanishes. CMake now correctly picks up our `ENV CC` variable, uses GCC 15 for compilation, and produces binaries compatible with our GCOV 15 analyzer.

However, solving one problem reveals another. The logs now show a new warning: `lcov: WARNING: (inconsistent) ...`. We have fixed the toolchain, but now we must tune the analyzer. This leads us to our next challenge.

# Chapter 7: The "Missing Language" - C/C++ and the Community Plugin

## 7.1 The "Paywall" Limitation

With our toolchain crisis resolved, the pipeline successfully completed a full execution. The compiler built our C, C++, Rust, and Python binaries using the correct GCC 15 instruction set. The scanner uploaded the report, and the dashboard populated.

But a quick audit of the SonarQube dashboard reveals a glaring omission. We see lines of code for **Python**. We see lines of code for **Rust**. But our **C** and **C++** implementations—which constitute the core performance logic of our "Hero Project"—are completely missing. They are not just reporting zero coverage; they are invisible.

This is not a configuration error; it is a feature gate.

The **SonarQube Community Build** explicitly excludes C and C++ analysis from its feature set. These languages are reserved for the paid **Developer Edition**. For a standard enterprise, paying for this feature is often the correct path. However, for our "First Principles" laboratory, we are operating under the constraint of using open-source infrastructure.

We cannot accept a partial view of our codebase. Our project contains distinct, idiomatic implementations in C23 and C++23. If we cannot inspect them, we cannot guarantee their quality. To solve this without breaking our budget, we must turn to the open-source ecosystem: the **Community C++ Plugin (`sonar-cxx`)**.

This plugin is a robust alternative to the official analyzer. It provides full support for C and C++ parsing, metric calculation, and—crucially for our next chapter—native ingestion of coverage reports. However, installing it into a containerized, immutable architecture presents a new logistical challenge.

## 7.2 The "Hot-Patch" Strategy

In a standard Docker build, we would simply add a `ADD` or `COPY` instruction to our `Dockerfile` to bake the plugin into the image. However, our architecture prevents this.

In **Article 5**, we made a deliberate architectural decision to persist the SonarQube extensions directory using a **Named Volume** (`sonarqube-extensions`). This ensures that if we upgrade the container image, we don't lose our installed plugins.

However, this persistence creates a deployment constraint: **Volume Masking**.
When Docker mounts a volume at `/opt/sonarqube/extensions`, it overlays the volume's contents on top of the container's filesystem. If we baked the plugin into the image at that path, the empty volume would mask it at runtime, effectively making it disappear.

Therefore, we cannot install this plugin at build time. We must perform a **"Hot-Patch."** We will download the plugin to our Host machine and inject it directly into the running container's volume stream.

**The "Toolkit" Trap**
Before we script this, we must heed a specific warning from the plugin maintainers. The release artifacts for `sonar-cxx` include two JAR files:
1.  `sonar-cxx-plugin-x.y.z.jar`: The actual plugin.
2.  `cxx-sslr-toolkit-x.y.z.jar`: A standalone command-line debugging tool.

It is a common mistake to copy *both* files into the plugins directory. **Do not do this.** The toolkit is not a SonarQube plugin; it lacks the required manifest metadata. If you place it in the plugins folder, SonarQube will attempt to load it, fail to find the plugin key, and crash the web server with a `java.lang.NullPointerException`. We must be surgical, installing only the plugin JAR.


## 7.3 The Installer Script (`06-install-cxx-plugin.sh`)

To execute this "Hot-Patch" reliably, we will encapsulate the logic in a script. This script acts as a bridge between the external open-source ecosystem and our internal, immutable infrastructure.

It performs a precise sequence of operations:

1.  **Fetch:** It downloads the specific, pinned version of the plugin (`2.2.1`) to the Host machine. This avoids relying on `wget` or `curl` being present inside the minimal SonarQube container image.
2.  **Clean:** It removes any existing versions of the plugin from the container's volume. This prevents version conflicts (e.g., having both v2.1 and v2.2 JARs loaded simultaneously), which causes startup crashes.
3.  **Inject:** It uses `docker cp` to surgically insert the JAR into the running container's file stream.
4.  **Secure:** It repairs the file permissions. Files copied from the host often arrive owned by `root`. SonarQube runs as `sonarqube` (UID 1000). If we don't fix this ownership, the application will crash with `Permission Denied` when it tries to load the class.
5.  **Reload:** It restarts the container to force the Java Classloader to pick up the new library.

Create this file at `~/cicd_stack/sonarqube/06-install-cxx-plugin.sh`.

```bash
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
# We pin the version to ensure reproducibility
PLUGIN_VERSION="2.2.1.1248"
PLUGIN_RELEASE="cxx-2.2.1"
PLUGIN_JAR="sonar-cxx-plugin-${PLUGIN_VERSION}.jar"
DOWNLOAD_URL="https://github.com/SonarOpenCommunity/sonar-cxx/releases/download/${PLUGIN_RELEASE}/${PLUGIN_JAR}"

CONTAINER_NAME="sonarqube"
CONTAINER_PLUGIN_DIR="/opt/sonarqube/extensions/plugins"

echo "Starting C++ Plugin Installation..."

# --- 1. Download Plugin to Host ---
# We download to the host first to avoid dependency issues inside the container
echo "Downloading $PLUGIN_JAR..."
wget -q --show-progress "$DOWNLOAD_URL"

if [ ! -f "$PLUGIN_JAR" ]; then
    echo "ERROR: Download failed."
    exit 1
fi

# --- 2. Remove Old Versions ---
# We check if an older version exists in the container and remove it
# to prevent classpath conflicts (having two versions of the same plugin).
echo "Checking for existing C++ plugins..."
docker exec "$CONTAINER_NAME" \
    bash -c "rm -f $CONTAINER_PLUGIN_DIR/sonar-cxx-plugin-*.jar"

# --- 3. Install New Plugin ---
echo "Installing new plugin..."
docker cp "$PLUGIN_JAR" "$CONTAINER_NAME:$CONTAINER_PLUGIN_DIR/"

# --- 4. Fix Permissions ---
# The file copied from host arrives owned by root.
# SonarQube runs as UID 1000. We must fix this or the app crashes.
echo "Fixing permissions..."
docker exec -u 0 "$CONTAINER_NAME" \
    chown 1000:1000 "$CONTAINER_PLUGIN_DIR/$PLUGIN_JAR"

# --- 5. Cleanup Host File ---
rm "$PLUGIN_JAR"

# --- 6. Restart SonarQube ---
echo "Restarting SonarQube to load plugin..."
docker restart "$CONTAINER_NAME"

echo "Plugin installed. Please verify in Administration > Marketplace > Installed."
```

### Execution

Run this script from your host machine:

```bash
chmod +x 06-install-cxx-plugin.sh
./06-install-cxx-plugin.sh
```

Once the script completes and SonarQube restarts (which may take 2 minutes), log in to the UI and navigate to **Administration \> Marketplace**. You should see the **CXX (Community)** plugin listed in the "Installed" tab. The engine is now capable of understanding C++.

## 7.4 Configuration: Enabling the Sensors

With the plugin physically present in the container's volume, we must now instruct the scanner to use it.

If you were to run the build immediately after the restart, the dashboard would likely remain unchanged. This is because SonarQube scanners operate on a strictly **Opt-In** basis for file extensions. The default Java scanner claims `.java` files; the Python scanner claims `.py` files. Since the Community Build has no native C++ scanner, `.cpp` and `.h` files are currently "orphaned"—they belong to no one, so they are ignored during the indexing phase.

We must explicitly assign these extensions to our new `cxx` plugin.

We do this by updating our client-side configuration file, `sonar-project.properties`. While we will provide a comprehensive breakdown of this file's architecture—including Analysis Scopes and Test definitions—in **Chapter 9**, for now, we focus on the single property required to wake up the C++ sensors.

**Action: Update `sonar-project.properties`**

Add the following line to your configuration file:

```properties
# --- LANGUAGE SPECIFICS ---
# The sonar-cxx plugin uses these suffixes to claim ownership of files
sonar.cxx.file.suffixes=.cxx,.cpp,.cc,.c,.h,.hpp
```

**Verification:**
Commit this change and trigger the **`0004_std_lib_http_client`** job in Jenkins.

When the analysis completes, check the SonarQube dashboard. You will notice a significant change:

1.  **Lines of Code:** The total count will jump. You will see a new entry for **C++** (or "CFamily") in the language breakdown.
2.  **Issues:** You may start seeing "Code Smells" or style warnings generated by the plugin's internal rules.
3.  **Coverage:** This will likely still be **0.0%**.

We have solved the **Indexing** problem (the files are visible), but we have not solved the **Metrics** problem. The plugin sees the code, but it cannot read the coverage report because the data format we are generating (LCOV) is clashing with the plugin's path resolution logic. This leads us to our next battle: The Data Format War.

# Chapter 8: The Data Format War - LCOV vs. Cobertura

## 8.1 The "Tower of Babel"

We have successfully "jailbroken" our Community Build. By injecting the `sonar-cxx` plugin, we forced the scanner to acknowledge the existence of our C++ code. If you look at the dashboard now, you will see our `.cpp` files listed in the "Code" tab, and the "Lines of Code" metric finally reflects reality.

However, a deeper look reveals a new failure. The **Coverage** column for C++ remains at **0.0%**, even though our Jenkins logs clearly show `lcov` successfully capturing data. We have the files, but we don't have the metrics.

To understand why, we must look at the scanner logs from our last build. Hidden amongst the success messages is a flood of warnings:

```text
WARN  Cannot sanitize file path './../src/c/httpc.c', ignoring coverage measures
WARN  Cannot sanitize file path './../src/cpp/httpcpp.cpp', ignoring coverage measures
```

This is a classic "Tower of Babel" problem. Our builder and our inspector are speaking different languages regarding **File Paths**.

1.  **The Builder's Perspective:** We executed our tests and coverage capture inside the `build_debug` directory. From that vantage point, the source code lives one directory up (`../src`). `lcov` faithfully recorded these relative paths in the tracefile.
2.  **The Inspector's Perspective:** The SonarQube Scanner runs from the **Project Root**. It expects all paths to be relative to the root (e.g., `src/c/httpc.c`).

When the plugin reads the LCOV file, it sees a record for `../src/c/httpc.c`. It tries to match this against the file index it built from the root. Since `../src` implies a path *outside* the project root, the sanitizer rejects it as a security risk or simply fails to map it. The data is discarded to prevent database corruption.

To fix this, we must align our perspectives. We need a format that is robust enough to handle path translation, or we need to change our execution context so the paths match naturally.

## 8.2 The Converter Strategy

We have two options to solve this.

The "Hacker" approach would be to use `sed` to rewrite the text inside the LCOV file, stripping the `../` prefix before the scanner sees it. This is fragile. If we ever change our build directory depth (e.g., `build/debug/x86`), our pipeline breaks.

The "First Principles" approach is to fix the **Execution Context**.

The relative paths are being generated because we are running the `lcov --capture` command *inside* the `build_debug` directory. To `lcov`, the source files *are* literally one level up.

If we move the execution of the capture command to the **Project Root**, the perspective changes. From the root, the source files are in `src/` and the object files are in `build_debug/`. If we tell `lcov` to capture from the root, it will generate paths starting with `src/`, which is exactly what SonarQube expects.

Additionally, we will convert this data into **Cobertura XML**. While the `sonar-cxx` plugin supports LCOV, the Cobertura format is the "Lingua Franca" of CI/CD. It is more widely supported by other tools (like Jenkins' own coverage view) and tends to be more robust against path quirks than raw LCOV tracefiles.

We will use a Python tool called `lcov_cobertura` to perform this translation on the fly. This fits perfectly into our polyglot agent, as we already have a Python environment available.

## 8.3 The Patch (`run-coverage-cicd.sh`)

We need to rewrite the C++ section of our coverage script to change *where* the commands run.

**The Changes:**

1.  **Context Switch:** We move the `lcov` capture logic *outside* the subshell that enters `build_debug`.
2.  **Base Directory:** We explicitly tell `lcov` that our base directory is the current folder (`.`), ensuring paths are calculated relative to the project root.
3.  **The Converter:** We install `lcov_cobertura` inside our existing Python virtual environment (to avoid PEP 668 system package errors) and use it to generate the final XML report.

Update your **`run-coverage-cicd.sh`** with the following logic:

```bash
#!/usr/bin/env bash
# ... (Header) ...

set -e

# --- 1. C/C++ Coverage (LCOV) ---
echo "--- Running C/C++ Tests & Coverage ---"

# A. Zero Counters (Run from Root, targeting build dir)
mkdir -p build_debug
lcov --directory build_debug --zerocounters --ignore-errors inconsistent,unused,negative -q

# B. Build & Run Tests (Inside build dir)
(
    cd build_debug || exit
    # Ensure Debug build for coverage flags
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    cmake --build . -- -j$(nproc)
    ctest --output-on-failure
)

# C. Capture & Filter (Run from Root)
# We capture from the root so paths like 'src/c/httpc.c' are relative to here.
lcov --capture \
     --directory build_debug \
     --output-file coverage.cxx.info \
     --ignore-errors inconsistent,unused,negative \
     --base-directory .

# Filter Artifacts
lcov --remove coverage.cxx.info \
     '/usr/*' \
     '*/_deps/*' \
     '*/tests/helpers.h' \
     '*/benchmark/*' \
     '*/apps/*' \
     '*/docs/*' \
     '*/cmake/*' \
     '*/.cache/*' \
     -o coverage.cxx.filtered.info \
     --ignore-errors inconsistent,unused,negative

# Rename for final use
mv coverage.cxx.filtered.info coverage.cxx.info

# ... (Rust Section Unchanged) ...

# --- 3. Python Coverage (XML) ---
echo "--- Running Python Tests & Installing Tools ---"
(
    if [ -d ".venv" ]; then
        . .venv/bin/activate
    fi
    cd src/python

    # Install lcov_cobertura here (inside the venv)
    python3 -m pip install --editable .[test] lcov_cobertura --quiet

    # Run Python Tests
    pytest -sv --cov=httppy --cov-report=xml:../../coverage.python.xml tests
)
echo "✅ Python coverage generated: coverage.python.xml"


# --- 4. Convert C++ LCOV to Cobertura XML (From Root) ---
echo "--- Converting C++ LCOV to Cobertura XML ---"
(
    # Activate the venv (using relative path from Root) to get access to lcov_cobertura
    if [ -f "src/python/.venv/bin/activate" ]; then
        . src/python/.venv/bin/activate
    elif [ -f ".venv/bin/activate" ]; then
        . .venv/bin/activate
    fi

    # Run conversion from ROOT so paths remain 'src/c/...' (matching the LCOV input)
    lcov_cobertura coverage.cxx.info --output coverage.cxx.xml
)
echo "✅ C/C++ Cobertura XML generated: coverage.cxx.xml"
```

## 8.4 Verification: Closing the Loop

We have successfully bridged the "Tower of Babel." Our coverage script now performs a sophisticated translation: it compiles in C++, captures in LCOV, translates to Cobertura XML, and aligns all file paths to the project root.

Now, we must tell the "Inspector" where to find this translated map.

We return to our `sonar-project.properties` file. Previously, we attempted to use `sonar.cxx.lcov.reportPath`. We must now replace this with the Cobertura-specific property supported by the community plugin.

**Action: Update `sonar-project.properties`**

```properties
# ... (Previous Python/Rust config) ...

# 3. C/C++ (Cobertura XML via sonar-cxx plugin)
# We replaced the LCOV property with the Cobertura property
# pointing to the file generated by our Python converter.
sonar.cxx.cobertura.reportPaths=coverage.cxx.xml
```

**The Final Test**

Commit this change and trigger the **`0004_std_lib_http_client`** job in Jenkins one last time.

When the build completes, open the SonarQube dashboard. You will witness the final piece of the puzzle falling into place:

1.  **Lines of Code:** C++ is present.
2.  **Issues:** C++ code smells are present.
3.  **Coverage:** The "0.0%" is gone. You should see a valid coverage percentage (likely \>90% given our test suite) for your `.cpp` files.

We have achieved what the official documentation implies is impossible for the Community Build: full, polyglot coverage analysis for C++, Rust, and Python in a single pipeline.

# Chapter 9: Tuning the Signal - Scopes and Exclusions

## 9.1 The "Low Signal" Mystery

With our format wars resolved, we triggered another build. The results on the SonarQube dashboard were a mixed bag of triumph and confusion.

On one hand, our **C++** coverage—previously a flat zero—had surged to over 90%, vindicating our efforts with the `sonar-cxx` plugin and the Cobertura converter. The scanner was successfully mapping the execution traces back to the source files.

On the other hand, our **Python** coverage sat at a dismal **24.8%**. Even more alarming, our **Rust** code showed no coverage data at all, despite our logs confirming that `cargo-llvm-cov` had run successfully.

We faced a new problem: **Signal-to-Noise Ratio**. We were piping data into the system, but the metrics were skewed. To understand why, we performed a forensic audit of the Python metrics.

Drilling down into the **Code** tab for the Python module, we found the culprit immediately. Files like `src/python/tests/test_httppy.py` were marked with a red bar indicating **0.0% Coverage**.

This revealed a fundamental misconfiguration in our **Analysis Scope**. By default, if you do not explicitly tell SonarQube otherwise, it assumes *every* file inside the `sonar.sources` directory is production code that must be tested.

Our pipeline was calculating the coverage **of** our tests, rather than the coverage **by** our tests.

Since test files generally do not test themselves, they report 0% coverage. In a project where the volume of test code roughly equals the volume of application code (a sign of a healthy project), this misconfiguration mathematically halts your coverage score at 50%. To fix this, we must teach the Inspector to distinguish between the *Target* (Source) and the *Evidence* (Tests).

## 9.2 Defining the Scope (`sonar.sources` vs. `sonar.tests`)

To fix this, we must explicitly define our **Analysis Scope** in `sonar-project.properties`. We need to decouple what is *scanned* from what is *measured*.

This requires a clear understanding of two properties that often confuse beginners:

1.  **`sonar.sources`**: This defines your **Production Code**. SonarQube will scan these files for bugs, code smells, and vulnerabilities. Crucially, these are the files that *must* be covered by tests. If a file is here, any uncovered line penalizes your score.
2.  **`sonar.tests`**: This defines your **Test Code**. SonarQube will scan these files for test-specific issues (e.g., "Assertion in a loop"), but it will **exempt** them from coverage calculations. It understands that these files exist to *provide* coverage, not to *consume* it.

Our fix is to physically separate our directories into these two buckets.

**Action: Update `sonar-project.properties`**

We will edit our properties file to explicitly list `src/python/tests` under `sonar.tests`, removing it from the default source scope.

```properties
# --- ANALYSIS SCOPE ---

# 1. Main Sources (Targets for Coverage)
# We include 'src' (code) and 'include' (C++ headers)
sonar.sources=src,include

# 2. Test Sources (Providers of Coverage)
# We explicitly list the top-level 'tests' folder AND the python-specific tests
sonar.tests=tests, src/python/tests
```

By making this distinction, we tell the Inspector: "Analyze `src/python/httppy` to see if it is tested. Analyze `src/python/tests` to see if the tests themselves are well-written, but do not demand that I write tests for my tests."

This single change instantly corrects the math, removing thousands of lines of "uncovered" test code from the denominator of our coverage equation.

## 9.3 Awakening Rust

While fixing Python, we also addressed the missing Rust data. Our investigation revealed a simple oversight: we were generating the report, but we never told SonarQube where to find it.

Unlike C++, which required a plugin and a format converter, **Rust** support in the Community Build is robust. The documentation confirms that the native Rust sensor supports **LCOV** ingestion out of the box.

We simply need to map the file we generated in our CI pipeline (`coverage.rust.info`) to the correct property key.

**Action: Update `sonar-project.properties`**

```properties
# --- COVERAGE REPORTING ---

# 2. Rust (LCOV)
# Native support in Community Edition requires this specific property.
# It tells the Rust sensor to read the LCOV file we generated with cargo-llvm-cov.
sonar.rust.lcov.reportPaths=coverage.rust.info
```

This is a "First Principles" lesson in configuration: tools are useless if they are disconnected. We spent effort generating the data, but without this single line of glue code, that effort was invisible to the system.

## 9.4 The Surgeon's Scalpel (Coverage Exclusions)

Finally, we apply a more granular tool: **Coverage Exclusions**.

Sometimes, you have code that *is* production code (it belongs in `sonar.sources`), but it is structurally impossible or architecturally unnecessary to unit test.

In our "Hero Project," our Rust implementation includes two binary entry points: `src/bin/httprust_client.rs` and `src/bin/reqwest_client.rs`. These files are thin wrappers—simple `main()` functions that parse arguments and call the library. Testing `main()` functions is notoriously difficult and often yields low value.

However, because they are in `src/`, SonarQube treats them as production code and penalizes us for their 0% coverage.

We do not want to use `sonar.exclusions`, because that would hide them completely. We *want* SonarQube to scan them for bugs (e.g., a memory leak in `main`). We just don't want them dragging down our coverage score.

The solution is **`sonar.coverage.exclusions`**.

```properties
# 3. Coverage Exclusions
# The Surgeon's Scalpel: Analyzed for bugs, but ignored for coverage stats.
# We exclude the Rust binaries (executables)
sonar.coverage.exclusions=src/rust/src/bin/**
```

This is the difference between a "blunt instrument" (hiding the file) and a "precision tool" (tuning the metric).

**The Payoff:**
With these three changes—splitting scopes, mapping Rust reports, and excluding entry points—we committed the configuration and ran the build.

The result was definitive. Our coverage score, once a broken 0% or a noisy 24%, stabilized at a rock-solid **94.1%**. We now have a clean, accurate signal.

## 9.5 The Blueprint: Deconstructing `sonar-project.properties`

We have modified our `sonar-project.properties` file iteratively throughout this process. Now, let us step back and analyze the complete, final "Blueprint" that drives our inspection.

This file is the single source of truth for the scanner. It bridges the gap between our source code structure and SonarQube's expectations.

```properties
# 1. Project Identification
# This key is the unique ID of the project in SonarQube's database.
# Since we imported this project from GitLab, we MUST use the key
# generated by SonarQube (e.g., with the UUID suffix).
# You can find this key in the SonarQube UI -> Project Information.
sonar.projectKey=articles_0004_std_lib_http_client_47ae4183-478d-4d13-bb80-86217c694444

# 2. Analysis Scope (The "What")
# sonar.sources defines Production Code (analyzed for bugs + coverage required).
# We include 'src' (application code) and 'include' (C++ headers).
sonar.sources=src,include

# sonar.tests defines Test Code (analyzed for bugs + NO coverage required).
# We explicitly move 'src/python/tests' here to fix our Python coverage ratio.
sonar.tests=tests, src/python/tests

# sonar.exclusions removes files from analysis entirely (invisible to SonarQube).
# We hide build artifacts (.o, .so) and temporary directories.
sonar.exclusions=build_debug/**, build_release/**, **/*.o, **/*.so, **/*.a, **/*.zip, **/*.crate, **/*.whl

# sonar.coverage.exclusions keeps files visible but ignores them for coverage stats.
# We use this for our Rust binary entry points, which are hard to unit test.
sonar.coverage.exclusions=src/rust/src/bin/**

# 3. Language Specifics
# We hint the scanner to use Python 3.12 parsing rules.
sonar.python.version=3.12
# We explicitly tell the 'sonar-cxx' plugin which extensions it owns.
sonar.cxx.file.suffixes=.cxx,.cpp,.cc,.c,.h,.hpp

# 4. Coverage Reporting (The "Evidence")
# Python: Native Cobertura XML support.
sonar.python.coverage.reportPaths=coverage.python.xml

# Rust: Native LCOV support (Community Build feature).
sonar.rust.lcov.reportPaths=coverage.rust.info

# C/C++: Cobertura XML support via the 'sonar-cxx' community plugin.
# Note that we point to the file generated by our lcov_cobertura converter.
sonar.cxx.cobertura.reportPaths=coverage.cxx.xml
```

### Where to find the Values

* **`sonar.projectKey`**: This is the most critical value. If you get this wrong, the scanner will create a *new* project instead of updating the existing one. You find this in the SonarQube UI:
    1.  Go to your Project Dashboard.
    2.  Click **Project Information** (usually on the right sidebar).
    3.  Copy the **Project Key**.
* **`sonar.sources` / `sonar.tests`**: These are relative paths from your repository root. You determine these by looking at your project structure (`ls -R`).
* **`sonar.*.reportPaths`**: These must match the output filenames defined in your `run-coverage-cicd.sh` script. Consistency between the shell script (Builder) and this properties file (Inspector) is mandatory.

# Chapter 10: The Gatekeeper - Enforcing MQR Standards

## 10.1 The Shift to MQR (Multi-Quality Rule) Mode

When you open your SonarQube dashboard for the first time after a successful analysis, you might notice that the terminology differs from older tutorials or legacy versions of the software.

In previous versions of SonarQube, issues were categorized into three rigid types: **Bugs**, **Vulnerabilities**, and **Code Smells**. While functional, this taxonomy often led to ambiguity. Is a memory leak a "Bug" or a "Code Smell"? Is a hardcoded password a "Vulnerability" or a "Security Hotspot"?

Modern SonarQube (specifically the v10.x and v25.x Community Builds we are using) has shifted to a new default paradigm called **MQR (Multi-Quality Rule) Mode**.

This mode reorients the analysis around three fundamental **Software Qualities**:

1.  **Reliability:** Will the software crash? Issues here include logic errors, unhandled exceptions, and memory leaks.
2.  **Security:** Can the software be exploited? Issues here include injection flaws, weak cryptography, and hardcoded secrets.
3.  **Maintainability:** Can the software be updated? Issues here include high cognitive complexity, duplicated blocks, and spaghetti code.

### The Severity Shift
Crucially, MQR Mode decouples the *Type* of issue from its *Severity*. An issue is no longer just "Critical" or "Minor." It is rated on a specific scale of impact for each quality dimension:

* **Blocker:** A high probability of high impact (e.g., a buffer overflow). Immediate fix required.
* **High:** High impact or high probability.
* **Medium:** Moderate impact.
* **Low:** Low impact.
* **Info:** Contextual information.

### The "Sonar way" Gate
This shift directly impacts how our **Quality Gate** functions.

The default "Sonar way" gate that is currently applied to our project does not simply say "No Bugs." It enforces specific MQR metrics on **New Code**:

* **Reliability Rating:** Must be **A** (No High/Blocker reliability issues).
* **Security Rating:** Must be **A** (No High/Blocker security issues).
* **Maintainability Rating:** Must be **A** (Technical Debt Ratio < 5%).
* **Coverage:** Must be **>= 80.0%**.
* **Duplicated Lines:** Must be **<= 3.0%**.

By understanding this taxonomy, we understand what is required to pass the gate. It is not enough to just "write tests" (Coverage); we must also write clean, secure code (MQR Ratings).


## 10.2 The Logic of the Gate (`waitForQualityGate`)

Now that we understand the criteria, we must examine the mechanism that enforces them.

In our **Article 9** pipeline, we simply uploaded artifacts. If the build produced a binary, we shipped it. In our updated `Jenkinsfile`, we introduced a critical new step:

```groovy
timeout(time: 5, unit: 'MINUTES') {
    waitForQualityGate abortPipeline: true
}
```

This step is not a simple "sleep" command. It is a sophisticated, asynchronous state machine.

1.  **The Handover:** When the `sonar-scanner` finishes uploading the report, it leaves behind a metadata file (`report-task.txt`) in the workspace. This file contains a **Compute Engine Task ID (`ceTaskId`)**.
2.  **The Pause:** The `waitForQualityGate` step reads this ID. It then puts the Jenkins pipeline into a "Paused" state. The heavy executor is released (depending on the agent configuration), and the job enters a lightweight listening mode.
3.  **The Processing:** On the SonarQube server, the Compute Engine processes the report, calculates the metrics, and compares them against the Quality Gate conditions.
4.  **The Callback:** Once the status is determined (OK or ERROR), SonarQube uses the **Webhook** we configured in Chapter 5 to call back to Jenkins. It sends a JSON payload containing the status for that specific `ceTaskId`.
5.  **The Decision:** Jenkins receives the webhook. If the payload says `status: "OK"`, the pipeline resumes and proceeds to the **Package** stage. If it says `status: "ERROR"`, the `abortPipeline: true` flag triggers an immediate build failure, stopping the conveyor belt before a bad artifact can be created.

## 10.3 The "Stop the Line" Verification

To prove that this system works, we must force a failure.

However, triggering a failure naturally can be difficult in a new environment. The default "Sonar way" gate only checks **New Code**. Since our coverage is currently high (94.1%), and we haven't introduced new bugs, our build is passing.

To simulate a "Bad Build," we will create a draconian Quality Gate that demands perfection—**100% Coverage**—and apply it to our project. Since we are at 94.1%, this is guaranteed to fail.

### Action 1: Create the "Fail-Hard" Gate

1.  Log in to SonarQube (`http://sonarqube.cicd.local:9000`).
2.  Navigate to **Quality Gates**.
3.  Click **Create**.
4.  **Name:** `fail-hard`.
5.  **Add Condition:**
    * **Where:** **Overall Code** (We want to fail immediately based on current state).
    * **Quality Gate fails when:** Select **Coverage**.
    * **Operator:** **is less than**.
    * **Value:** `100.0`.
6.  Click **Add Condition**.

### Action 2: Enforce the Gate

We must now assign this strict gate to our specific project.

1.  Navigate to the **`articles_...`** Project Dashboard.
2.  Click **Project Settings** \> **Quality Gate**.
3.  Select **Always use a specific Quality Gate**.
4.  Choose **`fail-hard`** from the dropdown.
5.  Click **Save**.

### Action 3: The Failed Build

Go to Jenkins and trigger the **`0004_std_lib_http_client`** job again.

**The Observation:**

1.  The **Test & Coverage** stage will pass (Green).
2.  The **Code Analysis** stage will start. The scanner will run.
3.  The pipeline will pause at `Checking status of SonarQube task...`.
4.  A few seconds later, the pipeline will turn **Red** and abort.

**The Evidence:**
If you check the Console Output, you will see:
`SonarQube task '...' Quality gate is 'ERROR'`
`Stage "Package" skipped due to earlier failure(s)`
`Stage "Publish" skipped due to earlier failure(s)`
`ERROR: Pipeline aborted due to quality gate failure: ERROR`

Crucially, if you check **Artifactory**, you will see that **no new artifacts were uploaded** for this build number. The system worked. The "Inspector" stopped the line, preventing a non-compliant product from reaching the warehouse.

You can now revert the Quality Gate setting in SonarQube back to **"Sonar way"** to restore the passing state.

## 10.4 Conclusion

We have reached a pivotal moment in our "City Planning."

With the deployment of SonarQube and the enforcement of the Quality Gate, our infrastructure has evolved from a simple "build loop" into a sophisticated **High-Assurance Software Supply Chain**.

Let's review the architectural state of our city:
1.  **The Library (GitLab):** Stores our blueprints securely.
2.  **The Factory (Jenkins):** Compiles our polyglot code using a precise, immutable toolchain (GCC 15/Python 3.12), resolving the binary incompatibility issues that plague manual builds.
3.  **The Inspector (SonarQube):** Analyzes the output using a custom-built image that trusts our internal PKI, ingesting data from three different languages (C++, Rust, Python) through a unified dashboard.
4.  **The Warehouse (Artifactory):** Receives *only* those artifacts that have passed the Inspector's rigorous MQR standards.

We have solved the "Quantity over Quality" problem. We are no longer filling our warehouse with time bombs. If a developer commits code that leaks memory or fails tests, the factory line stops immediately. The artifact is rejected. The system protects itself.

However, despite this sophistication, our city has one remaining flaw: **It is silent.**

When the Quality Gate slammed shut in our last test, the only way you knew was because you were staring at the Jenkins console. In a real team, developers push code and move on to the next task. They need to be notified *actively* when something breaks. They need the city to speak to them.

In the next article, we will install the "Public Address System" of our city. We will deploy **Mattermost**, an open-source ChatOps platform. We will connect it to our Factory and our Inspector, ensuring that when the line stops, the entire engineering team gets the alert instantly.