# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=import-error

import base64
import json
import os
import tempfile
from datetime import datetime

import pyclamd
from azure.data.tables import TableServiceClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueClient

CHUNK_SIZE = 1024 * 1024 * 1024


def get_config():
    return {
        "STORAGE_ACCOUNT": os.getenv("STORAGE_ACCOUNT"),
        "CLIENT_ID": os.getenv("CLIENT_ID"),
        "queue_name": os.getenv("queue_name") or "virus-scan",
        "result_queue_name": os.getenv("result_queue_name") or "clamav-scan-result",
        "quarantine_container_name": os.getenv("quarantine_container_name") or "datahub-quarantine",
        "datahub_container_name": os.getenv("container_name") or "datahub",
        "WORK_DIR": os.getenv("WORK_DIR") or "/datahub-temp",
        "ENABLE_QUARANTINE": os.getenv("ENABLE_QUARANTINE") or "false",
    }


config = get_config()
queue_client = None
result_queue_client = None
blob_service_client = None
table_service_client = None


def initialize_clients():
    """Create Azure clients only when the worker starts.

    Keeping this work out of module import lets unit tests import the worker
    without Azure configuration or credential discovery.
    """
    global blob_service_client, queue_client, result_queue_client, table_service_client

    credential = DefaultAzureCredential(managed_identity_client_id=config["CLIENT_ID"])
    account_url = f"https://{config['STORAGE_ACCOUNT']}"
    queue_client = QueueClient(
        account_url=f"{account_url}.queue.core.windows.net/",
        queue_name=config["queue_name"],
        credential=credential,
    )
    result_queue_client = QueueClient(
        account_url=f"{account_url}.queue.core.windows.net/",
        queue_name=config["result_queue_name"],
        credential=credential,
    )
    blob_service_client = BlobServiceClient(account_url=f"{account_url}.blob.core.windows.net/", credential=credential)
    table_service_client = TableServiceClient(endpoint=f"{account_url}.table.core.windows.net/", credential=credential)


def scan_blob(blob_client, blob_full_name, clamav_socket):
    blob_size = blob_client.get_blob_properties().size
    chunk_start = 0
    chunk_index = 0
    threats = []

    while chunk_start < blob_size:
        chunk_end = min(chunk_start + CHUNK_SIZE, blob_size) - 1
        print(f"FSDH - Downloading chunk {chunk_index} to tempfile: bytes {chunk_start} to {chunk_end}")

        with tempfile.NamedTemporaryFile(delete=True, suffix="filechunk") as temp_file:
            print(f"FSDH - chunk scan as tempfile: {blob_full_name} chunk {chunk_index} tempfile {temp_file.name}")
            with open(temp_file.name, "wb") as file:
                download = blob_client.download_blob(offset=chunk_start, length=chunk_end - chunk_start + 1)
                file.write(download.readall())
                os.chmod(temp_file.name, 0o666)

            print("FSDH - temp file:", os.path.getsize(temp_file.name), "readable", os.access(temp_file.name, os.R_OK))
            result = clamav_socket.scan_file(temp_file.name)
            print(f"FSDH - chunk scan completed: {blob_full_name} chunk {chunk_index}")

            if result is None:
                print(f"FSDH - scan result None: {blob_full_name} chunk {chunk_index}")
            else:
                for filename, (status, virus) in result.items():
                    if status == "FOUND":
                        print(f"FSDH - chunk result FOUND: {blob_full_name} chunk {chunk_index} {filename} {virus}")
                        threats.append(virus)
                    elif status == "OK":
                        print(f"FSDH - chunk result OK: {blob_full_name} chunk {chunk_index} {filename}")
                    else:
                        print(f"FSDH - chunk result {status}{virus}")

            if threats:
                print(f"FSDH - Infected blob chunk {chunk_index}: {blob_full_name}")
                break

            if "clamavtest2025a" in blob_full_name:
                threats.append("Testing...file name include clamavtest2025a")
                break

            print(f"FSDH - blob chunk {chunk_index} is clean: {blob_full_name}")

        chunk_start += CHUNK_SIZE
        chunk_index += 1

    return threats


def split_blob_path(blob_name_full: str) -> tuple[str, str, str, str]:
    parts = blob_name_full.strip("/").split("/")
    container_index = parts.index("containers") + 1
    blob_index = parts.index("blobs", container_index) + 1
    container = parts[container_index]
    blob_in_container = "/".join(parts[blob_index:])
    return container, blob_in_container, f"/{container}/{blob_in_container}", blob_name_full


def process_message(message):
    json_data = json.loads(base64.b64decode(message.content))
    blob_name_container, blob_name_in_container, blob_name_with_container, blob_name_full = split_blob_path(
        json_data["subject"]
    )
    blob_url = json_data["data"]["blobUrl"]

    print(f"FSDH - processing blob: {blob_name_full}")
    if blob_name_container not in config["datahub_container_name"].lower().split(","):
        print(
            f"FSDH - skipping blob {blob_name_full} not in target containers: {config['datahub_container_name'].lower()}"
        )
        return

    blob_client = blob_service_client.get_blob_client(container=blob_name_container, blob=blob_name_in_container)
    if not blob_client.exists():
        print(f"FSDH - blob Not found: {blob_name_in_container} at {blob_url}")
        return

    scan_start_time = datetime.now()
    scan_result = scan_blob(blob_client, blob_name_full, pyclamd.ClamdUnixSocket())
    scan_end_time = datetime.now()
    more_blob_metadata = {"avscan": "ok"}

    if scan_result:
        print(f"FSDH - Infected blob {blob_name_full}")
        try:
            infected_blob_client = blob_service_client.get_blob_client(
                container=config["quarantine_container_name"],
                blob=f"{blob_name_container}/{blob_name_in_container}",
            )
            if infected_blob_client.exists():
                print(f"FSDH - blob {blob_name_in_container} already exists in quarantine container, deleting")
                infected_blob_client.delete_blob()

            if config["ENABLE_QUARANTINE"].lower() == "true":
                print(f"FSDH - copying blob {blob_name_in_container} to quarantine container")
                infected_blob_client.start_copy_from_url(blob_client.url)

            table_client = table_service_client.get_table_client(table_name="infectedfiles")
            entity = {
                "PartitionKey": blob_name_with_container.replace("/", "|||"),
                "RowKey": f"{datetime.now().isoformat()}Z",
                "fileName": blob_name_with_container,
                "threats": json.dumps(scan_result),
            }
            table_client.create_entity(entity=entity)
        finally:
            more_blob_metadata = {"avscan": "fail", "avscan_reason": json.dumps(scan_result)}
            if config["ENABLE_QUARANTINE"].lower() == "true":
                blob_client.delete_blob()

    blob_metadata = blob_client.get_blob_properties().metadata
    blob_metadata.update(more_blob_metadata)
    blob_client.set_blob_metadata(metadata=blob_metadata)
    result_queue_client.send_message(
        json.dumps(
            {
                "ScanStartTime": scan_start_time.isoformat(),
                "ScanEndTime": scan_end_time.isoformat(),
                "ScanError": json.dumps(scan_result) if scan_result else "",
                "ScannedFile": blob_url,
            }
        )
    )


def main():
    initialize_clients()
    messages = queue_client.receive_messages(messages_per_page=10, visibility_timeout=14400)
    for msg_batch in messages.by_page():
        for message in msg_batch:
            try:
                process_message(message)
                queue_client.delete_message(message)
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"FSDH - Error processing message: {error}")
                queue_client.update_message(message=message, visibility_timeout=3600 * 8)


if __name__ == "__main__":  # pragma: no cover
    main()
