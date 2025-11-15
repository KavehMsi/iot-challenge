# Project README

This project provides tooling to configure and manage a Suricata instance using environment variables. The variables control Suricata tuning, capture configuration, ruleset selection, logging behavior, and Docker runtime options.

---

## Environment Variables

Below is a description of each environment variable, whether it is required, and what it controls.

### **SCTL_DEVICE_ID** (required)

A unique identifier for the sensor or device. Used in metadata and logs to distinguish this Suricata instance.

### **SCTL_IFACE** (required)

The network interface used for packet capture. Must be a valid system interface.

### **SCTL_CAPTURE** (required)

Determines the capture method Suricata will use.
Allowed values:

* `AF_PACKET`
* `PCAP`

### **SCTL_CPU_WORKERS** (required)

Number of packet-processing threads. Must not exceed available CPU cores.

### **SCTL_MEMCAP_MB** (required)

Flow memory allocation in megabytes. Must be validated against system memory capacity.

### **SCTL_PROFILE** (required)

Suricata detection engine profile.
Allowed values:

* `connectivity`
* `balanced`
* `security`
* `performance`

### **SCTL_RULESET** (required)

Comma-separated list of Suricata ruleset files to load.
Example:

```
SCTL_RULESET="et-open.rules,local.rules"
```

### **SCTL_LOG_ROTATE_MB** (required)

Maximum log size (in MB) before log rotation is triggered.

### **SCTL_LOG_RETENTION_DAYS** (required)

Number of days to retain rotated log files.

### **SCTL_SURICATA_CONFIG** (required)

Path to the Suricata YAML configuration file that will be modified.

### **SCTL_SURICATA_CLASSIFICATION** (optional)

Optional path to Suricata's classification file.

### **SCTL_SURICATA_REFERENCE** (optional)

Optional path to the reference configuration file.

### **SCTL_SURICATA_THRESHOLD** (optional)

Optional path to the threshold configuration file.

### **SCTL_SURICATA_UPDATE** (optional)

Boolean. If set to true, Suricata rules will be updated before startup.

### **SCTL_DOCKER_IMAGE** (optional)

Name of the Docker image to run Suricata inside.

### **SCTL_CONTAINER_NAME** (optional)

Name of the container instance if running Suricata via Docker.

### **SCTL_DOCKER_VOLUME** (optional)

Docker volume mount path for persistent logs or configuration.

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd <project-directory>
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file or export them manually.
Example `.env`:

```
SCTL_DEVICE_ID=sensor01
SCTL_IFACE=eth0
SCTL_CAPTURE=AF_PACKET
SCTL_CPU_WORKERS=4
SCTL_MEMCAP_MB=1024
SCTL_PROFILE=balanced
RULESET=et-open.rules,local.rules
SCTL_LOG_ROTATE_MB=100
SCTL_LOG_RETENTION_DAYS=14
SCTL_SURICATA_CONFIG=/etc/suricata/suricata.yaml
```

### 5. Run the Controller

```bash
./.venv/bin/python3 suricata_ctl/suricata_ctl.py --start
```

---

## Commands

### `--start`

Starts a new Suricata Docker instance if none is running. It generates and applies the Suricata configuration based on environment variables and configures log rotation and retention through Linux logrotate.

### `--stop`

Stops the Suricata Docker container if one is running.

### `--clean-up`

Used together with `--stop` to remove Suricata log files after stopping the container.

---

## Notes

* Ensure your user has permission to run Docker (if used).
* When writing to system locations (e.g., logrotate config), run the script with sudo while preserving environment variables.
* All required variables must be set or validation will fail.

---

This project provides a flexible way to fully configure Suricata dynamically from environment variables, supporting both host and Docker-based deployments.
