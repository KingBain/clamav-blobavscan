# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=import-error

import base64
import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime

import pyclamd
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueClient

CHUNK_SIZE = 1024 * 1024 * 1024
COPY_TIMEOUT_SECONDS = 300
COPY_POLL_INTERVAL_SECONDS = 1


@dataclass
class RuntimeState:
    config: dict | None = None
    queue_client: QueueClient | None = None
    result_queue_client: QueueClient | None = None
    blob_service_client: BlobServiceClient | None = None
    table_service_client: TableServiceClient | None = None


RUNTIME = RuntimeState()


def get_config():
    return {
        "STORAGE_ACCOUNT": os.getenv("STORAGE_ACCOUNT"),
        "CLIENT_ID": os.getenv("CLIENT_ID"),
        "queue_name": os.getenv("queue_name") or "virus-scan",
        "result_queue_name": os.getenv("result_queue_name") or "clamav-scan-result",
        "quarantine_container_name": (os.getenv("quarantine_container_name") or "datahub-quarantine"),
        "datahub_container_name": os.getenv("container_name") or "datahub",
        "WORK_DIR": os.getenv("WORK_DIR") or "/datahub-temp",
        "ENABLE_QUARANTINE": os.getenv("ENABLE_QUARANTINE") or "false",
    }


def initialize_clients(app_config):
    storage_account = app_config["STORAGE_ACCOUNT"]

    if not storage_account:
        raise ValueError("STORAGE_ACCOUNT is required")

    credential = DefaultAzureCredential(managed_identity_client_id=app_config["CLIENT_ID"])

    RUNTIME.config = app_config

    RUNTIME.queue_client = QueueClient(
        account_url=f"https://{storage_account}.queue.core.windows.net/",
        queue_name=app_config["queue_name"],
        credential=credential,
    )

    RUNTIME.result_queue_client = QueueClient(
        account_url=f"https://{storage_account}.queue.core.windows.net/",
        queue_name=app_config["result_queue_name"],
        credential=credential,
    )

    RUNTIME.blob_service_client = BlobServiceClient(
        account_url=f"https://{storage_account}.blob.core.windows.net/",
        credential=credential,
    )

    RUNTIME.table_service_client = TableServiceClient(
        endpoint=f"https://{storage_account}.table.core.windows.net/",
        credential=credential,
    )


def scan_blob(
    blob_client,
    blob_full_name,
    clamav_socket,
    chunk_size=CHUNK_SIZE,
    work_dir=None,
):
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    blob_properties = blob_client.get_blob_properties()
    blob_size = blob_properties.size

    chunk_start = 0
    chunk_index = 0
    threats = []

    while chunk_start < blob_size:
        chunk_end = min(chunk_start + chunk_size, blob_size) - 1

        print(f"FSDH - Downloading chunk {chunk_index} to tempfile: bytes {chunk_start} to {chunk_end}")

        with tempfile.NamedTemporaryFile(
            delete=True,
            suffix="filechunk",
            dir=work_dir,
        ) as temp_file:
            print(
                f"FSDH - chunk scan as tempfile: {blob_full_name} "
                f"chunk {chunk_index} tempfile {temp_file.name}"
            )

            download = blob_client.download_blob(
                offset=chunk_start,
                length=chunk_end - chunk_start + 1,
            )

            with open(temp_file.name, "wb") as file:
                file.write(download.readall())

            os.chmod(temp_file.name, 0o666)

            print(
                "FSDH - temp file:",
                os.path.getsize(temp_file.name),
                "readable",
                os.access(temp_file.name, os.R_OK),
            )

            result = clamav_socket.scan_file(temp_file.name)

            print(f"FSDH - chunk scan completed: {blob_full_name} chunk {chunk_index}")

            threat_found = False

            if result is None:
                print(f"FSDH - scan result None: {blob_full_name} chunk {chunk_index}")
            else:
                for filename, scan_details in result.items():
                    status, virus = scan_details

                    if status == "FOUND":
                        threat_found = True
                        threats.append(virus)

                        print(
                            f"FSDH - chunk result FOUND: "
                            f"{blob_full_name} chunk {chunk_index} "
                            f"{filename} {virus}"
                        )

                    elif status == "OK":
                        print(f"FSDH - chunk result OK: {blob_full_name} chunk {chunk_index} {filename}")

                    else:
                        print(
                            f"FSDH - chunk result {status}: "
                            f"{blob_full_name} chunk {chunk_index} "
                            f"{filename} {virus}"
                        )

            if threat_found:
                print(f"FSDH - Infected blob chunk {chunk_index}: {blob_full_name}")
                break

            print(f"FSDH - blob chunk {chunk_index} is clean: {blob_full_name}")

        chunk_start += chunk_size
        chunk_index += 1

    return threats


def split_blob_path(blob_name_full):
    parts = blob_name_full.strip("/").split("/")

    valid_path = len(parts) >= 6 and parts[2] == "containers" and parts[4] == "blobs"

    if not valid_path:
        raise ValueError(f"Invalid Azure Blob Storage event subject: {blob_name_full}")

    container = parts[3]
    blob_in_container = "/".join(parts[5:])

    if not container or not blob_in_container:
        raise ValueError(f"Invalid Azure Blob Storage event subject: {blob_name_full}")

    blob_name_with_container = f"/{container}/{blob_in_container}"

    return (
        container,
        blob_in_container,
        blob_name_with_container,
        blob_name_full,
    )


def get_copy_status(copy_properties):
    if copy_properties is None:
        return None, None

    if isinstance(copy_properties, dict):
        return (
            copy_properties.get("status"),
            copy_properties.get("status_description"),
        )

    return (
        getattr(copy_properties, "status", None),
        getattr(copy_properties, "status_description", None),
    )


def wait_for_copy_completion(quarantine_blob_client):
    deadline = time.monotonic() + COPY_TIMEOUT_SECONDS

    while True:
        blob_properties = quarantine_blob_client.get_blob_properties()

        status, status_description = get_copy_status(getattr(blob_properties, "copy", None))

        if status == "success":
            return

        if status in ("failed", "aborted"):
            raise RuntimeError(f"Blob copy {status}: {status_description or 'no details available'}")

        if time.monotonic() >= deadline:
            raise TimeoutError(f"Blob copy did not finish within {COPY_TIMEOUT_SECONDS} seconds")

        time.sleep(COPY_POLL_INTERVAL_SECONDS)


def record_infected_file(
    blob_name_with_container,
    scan_result,
):
    if RUNTIME.table_service_client is None:
        raise RuntimeError("Table service client has not been initialized")

    table_client = RUNTIME.table_service_client.get_table_client(table_name="infectedfiles")

    entity = {
        "PartitionKey": blob_name_with_container.replace("/", "|||"),
        "RowKey": datetime.now().isoformat() + "Z",
        "fileName": blob_name_with_container,
        "threats": json.dumps(scan_result),
    }

    print("FSDH - inserting infected file into storage table")

    table_client.create_entity(entity=entity)


def move_blob_to_quarantine(
    source_blob_client,
    source_container,
    source_blob_name,
    updated_metadata,
    app_config,
):
    if RUNTIME.blob_service_client is None:
        raise RuntimeError("Blob service client has not been initialized")

    quarantine_blob_client = RUNTIME.blob_service_client.get_blob_client(
        container=app_config["quarantine_container_name"],
        blob=f"{source_container}/{source_blob_name}",
    )

    if quarantine_blob_client.exists():
        print(f"FSDH - blob {source_blob_name} already exists in quarantine container, deleting")

        quarantine_blob_client.delete_blob()

    print(f"FSDH - copying blob {source_blob_name} to quarantine container")

    quarantine_blob_client.start_copy_from_url(source_blob_client.url)

    wait_for_copy_completion(quarantine_blob_client)

    # Ensure the quarantined file contains the antivirus result metadata.
    quarantine_blob_client.set_blob_metadata(metadata=updated_metadata)

    # Delete the source only after the quarantine copy completes.
    source_blob_client.delete_blob()


def create_result_message(
    *,
    blob_url,
    scan_start_time,
    scan_end_time,
    scan_result,
    original_metadata,
    updated_metadata,
):
    return {
        "ScanStartTime": scan_start_time.isoformat(),
        "ScanEndTime": scan_end_time.isoformat(),
        "ScanError": json.dumps(scan_result) if scan_result else "",
        "ScannedFile": blob_url,
        "OriginalBlobMetadata": original_metadata,
        "UpdatedBlobMetadata": updated_metadata,
    }


def process_message(message, app_config=None):
    if app_config is None:
        app_config = RUNTIME.config

    if app_config is None:
        raise RuntimeError("Application configuration has not been initialized")

    event = json.loads(base64.b64decode(message.content))

    (
        blob_name_container,
        blob_name_in_container,
        blob_name_with_container,
        blob_name_full,
    ) = split_blob_path(event["subject"])

    blob_url = event["data"]["blobUrl"]

    print(f"FSDH - processing blob: {blob_name_full}")

    target_containers = [
        item.strip().lower() for item in app_config["datahub_container_name"].split(",") if item.strip()
    ]

    if blob_name_container.lower() not in target_containers:
        print(
            f"FSDH - skipping blob {blob_name_full} "
            f"not in target containers: "
            f"{app_config['datahub_container_name']}"
        )
        return None

    if RUNTIME.blob_service_client is None:
        raise RuntimeError("Blob service client has not been initialized")

    blob_client = RUNTIME.blob_service_client.get_blob_client(
        container=blob_name_container,
        blob=blob_name_in_container,
    )

    if not blob_client.exists():
        print(f"FSDH - blob not found: {blob_name_in_container} at {blob_url}")
        return None

    blob_properties = blob_client.get_blob_properties()

    original_metadata = dict(blob_properties.metadata or {})

    clamav_socket = pyclamd.ClamdUnixSocket()

    scan_start_time = datetime.now()

    scan_result = scan_blob(
        blob_client,
        blob_name_full,
        clamav_socket,
        work_dir=app_config["WORK_DIR"],
    )

    scan_end_time = datetime.now()

    updated_metadata = dict(original_metadata)

    if scan_result:
        print(f"FSDH - Infected blob {blob_name_full}")

        updated_metadata["avscan"] = "fail"
        updated_metadata["avscan_reason"] = json.dumps(scan_result)

        record_infected_file(
            blob_name_with_container,
            scan_result,
        )

        quarantine_enabled = app_config["ENABLE_QUARANTINE"].lower() == "true"

        if quarantine_enabled:
            move_blob_to_quarantine(
                source_blob_client=blob_client,
                source_container=blob_name_container,
                source_blob_name=blob_name_in_container,
                updated_metadata=updated_metadata,
                app_config=app_config,
            )
        else:
            blob_client.set_blob_metadata(metadata=updated_metadata)

    else:
        updated_metadata["avscan"] = "ok"
        updated_metadata.pop("avscan_reason", None)

        blob_client.set_blob_metadata(metadata=updated_metadata)

    result_message = create_result_message(
        blob_url=blob_url,
        scan_start_time=scan_start_time,
        scan_end_time=scan_end_time,
        scan_result=scan_result,
        original_metadata=original_metadata,
        updated_metadata=updated_metadata,
    )

    if RUNTIME.result_queue_client is None:
        raise RuntimeError("Result queue client has not been initialized")

    RUNTIME.result_queue_client.send_message(json.dumps(result_message))

    return result_message


def main(process_function=None):
    if process_function is None:
        process_function = process_message

    if RUNTIME.queue_client is None:
        raise RuntimeError("Queue client has not been initialized")

    queue_client = RUNTIME.queue_client

    messages = queue_client.receive_messages(
        messages_per_page=10,
        visibility_timeout=14400,
    )

    for message_batch in messages.by_page():
        for message in message_batch:
            try:
                process_function(message)
                queue_client.delete_message(message)

            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"FSDH - Error processing message: {error}")

                queue_client.update_message(
                    message=message,
                    visibility_timeout=3600 * 8,
                )


def run():
    app_config = get_config()

    initialize_clients(app_config)

    main()


if __name__ == "__main__":  # pragma: no cover
    run()