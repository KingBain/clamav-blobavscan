# Local End-to-End (E2E) Test Suite

This folder contains a fully localized End-to-End (E2E) test suite for the ClamAV Blob Scanner. 

It uses [Azurite](https://github.com/Azure/Azurite) to emulate Azure Blob and Queue storage, allowing us to test the entire application lifecycle—from event consumption to scanning and metadata updating—**without requiring an active Azure subscription or cloud resources.**

## 🚀 How to Run

To run the test suite, simply execute the runner script from anywhere in the repository:

```bash
./tests/local-e2e/run.sh
```

If the test is successful, it will exit silently (or print a success message) and clean up after itself. If it fails, it will automatically dump the container logs to your terminal so you can see what went wrong.

---

## 🧩 How It Works

The test is orchestrated by `run.sh`, which uses Docker Compose (`compose.yaml`) to spin up four distinct services in order:

### 1. `azurite` (The Storage Emulator)
Spins up Microsoft's official Azurite container. It binds to local ports to simulate Azure Blob Storage (port 10000) and Azure Queue Storage (port 10001) using a dummy storage account and access key.

### 2. `setup` (The Test Fixture)
Runs `setup.py`. This script waits for Azurite to become healthy, then:
* Creates the required Blob Storage container (`datahub`) and Queues (`virus-scan`, `clamav-scan-result`).
* Uploads a dummy text file (`local-e2e/clean.txt`).
* Generates a mock Azure Event Grid `Blob-created` payload and pushes it into the `virus-scan` queue.

### 3. `scanner` (The Application)
Builds and runs the **actual production Dockerfile** from the root of the repository. 
* It connects to Azurite using a dummy `STORAGE_CONNECTION_STRING`.
* `freshclam` runs to download the latest virus definitions.
* The Python worker reads the event from the queue, downloads the blob, scans it, and writes the results back to the Blob's metadata and the output queue.

### 4. `verify` (The Assertion)
Runs `verify.py`. This script connects to Azurite and strictly asserts that:
* The original blob's metadata was successfully updated to `{"avscan": "ok"}`.
* A JSON payload was written to the `clamav-scan-result` queue.
* The JSON payload contains the correct output format (no errors, expected metadata).

If all `assert` statements in `verify.py` pass, the test is considered successful.

---

## 🧹 Cleanup & Error Handling

The `run.sh` script uses a bash `trap` to ensure resources are cleaned up.

* **On Success:** The `trap cleanup EXIT` triggers, shutting down all Docker Compose containers and securely wiping the Azurite storage volumes (`docker compose down --volumes --remove-orphans`).
* **On Failure:** If *any* step fails (thanks to `set -euo pipefail`), the trap triggers, detects the non-zero exit code, and runs `docker compose logs` so you can immediately see the stack trace or ClamAV error before the test environment is torn down.

## 🛠️ Modifying the Test

* **Adding Infected File Tests:** Currently, this tests a clean file. You could easily duplicate `setup.py` and `verify.py` to create a `test-infected` scenario that uploads the EICAR test string and asserts that `{"avscan": "fail"}` is applied (or that the quarantine flow is triggered).
* **Verbose Output:** If you want explicit confirmation that the E2E passed, you can add an `echo "E2E Passed!"` to the bottom of `run.sh` or a `print("Success!")` to the bottom of `verify.py`.
