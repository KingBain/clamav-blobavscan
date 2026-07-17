"""Create local storage resources and enqueue one Blob-created event."""

import base64
import json
import os
import time

from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueClient

CONNECTION_STRING = os.environ["STORAGE_CONNECTION_STRING"]
CONTAINER = os.environ["container_name"]
QUEUE = os.environ["queue_name"]
RESULT_QUEUE = os.environ["result_queue_name"]
BLOB_NAME = "local-e2e/clean.txt"


def retry(operation):
    for attempt in range(30):
        try:
            return operation()
        except Exception:  # Azurite may still be starting.
            if attempt == 29:
                raise
            time.sleep(1)


def main():
    blob_service = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    retry(lambda: blob_service.create_container(CONTAINER))
    blob_client = blob_service.get_blob_client(CONTAINER, BLOB_NAME)
    blob_client.upload_blob(b"A harmless local end-to-end test file.\n", overwrite=True)

    event = {
        "subject": f"/blobServices/default/containers/{CONTAINER}/blobs/{BLOB_NAME}",
        "data": {"blobUrl": blob_client.url},
    }
    encoded_event = base64.b64encode(json.dumps(event).encode("utf-8")).decode("ascii")

    queue_client = QueueClient.from_connection_string(CONNECTION_STRING, QUEUE)
    result_queue_client = QueueClient.from_connection_string(CONNECTION_STRING, RESULT_QUEUE)
    retry(queue_client.create_queue)
    result_queue_client.create_queue()
    queue_client.send_message(encoded_event)


if __name__ == "__main__":
    main()
