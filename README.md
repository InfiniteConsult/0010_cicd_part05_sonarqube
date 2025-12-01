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