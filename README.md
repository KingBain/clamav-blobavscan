# ClamAV Blob Antivirus Scanner

This containerized service scans Azure Blob Storage objects for viruses using **ClamAV**, automatically quarantining infected files and reporting scan results.

It’s designed to run as a background worker, consuming Azure Storage Queue messages that notify it of new or updated blobs.

---

## ✨ Features

- ✅ **Antivirus scanning with ClamAV**
- ✅ **Azure Blob Storage integration** (download & upload blobs)
- ✅ **Azure Queue integration** (consume messages about new blobs)
- ✅ **Automatic quarantining** of infected files
- ✅ **Configurable via environment variables**
- ✅ **Lightweight container image built on Ubuntu 24.04**
- ✅ **Pinned to amd64 architecture** for consistent builds

---

## 📂 Project Structure

```none
managed-containers/clamav-blobavscan/
├── Dockerfile             # Builds the container image
├── base_packages.list     # OS-level dependencies
├── README.md
└── app/
    ├── entrypoint.sh      # Container startup script
    ├── requirements.txt   # Python dependencies
    └── scan_blob.py       # Main scanning logic
```

---

## 🏗️ How It Works

1. Azure Queue receives a blob event notification (new or updated blob).
2. The container downloads the blob from Azure Blob Storage to a temporary location.
3. ClamAV scans the blob.
4. If clean ✅ → the blob remains in its original container.
5. If infected ❌ → the blob is deleted and a plain text with the same blob name is created in the quarantine container (TBD).

---

## 🔧 Configuration

| Variable                    | Description                               | Default              |
| --------------------------- | ----------------------------------------- | -------------------- |
| `storage_connection_string` | Azure Storage connection string           | _required_           |
| `queue_name`                | Queue name containing blob events         | `blob-created`       |
| `container_name`            | Name of the container with incoming blobs | `datahub`            |
| `quarantine_container_name` | Name of the quarantine container          | `datahub-quarantine` |
| `AzureTenantId`             | Azure tenant (optional placeholder)       |                      |
| `AzureSubscriptionId`       | Azure subscription (optional placeholder) |                      |
| `DataHub_ENVNAME`           | Environment name (e.g. `dev`)             | `dev`                |

---

## 🚀 Quick Start

### 1️⃣ Build the image

```bash
docker build --platform linux/amd64 -t clamav-blobavscan .
```

> **Why `--platform linux/amd64`?** The base image is pinned to an amd64 digest for reproducibility, avoiding architecture mismatch issues.

### 2️⃣ Run locally

```bash
docker run --platform linux/amd64 --rm \
  -e storage_connection_string="YOUR_CONNECTION_STRING" \
  -e queue_name="blob-created" \
  -e container_name="datahub" \
  -e quarantine_container_name="datahub-quarantine" \
  clamav-blobavscan
```

The container will:

- Update ClamAV definitions (`freshclam`)
- Start scanning queued blob events

---

## 🏗️ Deployment

This scanner is designed for:

- **Azure Functions** with custom containers
- **Kubernetes** as a worker pod
- **Standalone container execution**

Requirements:

- An **Azure Storage Queue** receiving blob event notifications
- Proper IAM/Access keys for the container to access blob storage

---

## 📦 Dependencies

### OS Packages

Defined in `base_packages.list`, including:

- **ClamAV**
- **curl / wget / unzip**
- **Python3 + venv**

### Python Dependencies

From `requirements.txt`:

- `azure-storage-blob`
- `azure-storage-queue`
- `azure-identity`
- `azure-keyvault`

---

## 🛠️ Development

Run the container in interactive mode for debugging:

```bash
docker run -it --entrypoint bash clamav-blobavscan
```

Inside the container:

```bash
freshclam    # update virus DB
. /opt/venv/bin/activate
python3 scan_blob.py
```

---

## ⚠️ Notes on Reproducibility

- **Base Image Digest** — To update the pinned digest:

  ```bash
  docker buildx imagetools inspect ubuntu:24.04 | grep amd64
  ```

  Replace the digest in the Dockerfile with the latest amd64 SHA.

- **APT Snapshotting** — (`APT::Snapshot`) to lock package versions in time.