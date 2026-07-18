"""Assert that the scanner updated Blob metadata and produced a result event."""

import json
import os

from azure.storage.blob import BlobServiceClient
from azure.storage.queue import QueueClient

CONNECTION_STRING = os.environ["STORAGE_CONNECTION_STRING"]
CONTAINER = os.environ["container_name"]
BLOB_NAME = "local-e2e/clean.txt"
RESULT_QUEUE = os.environ["result_queue_name"]

def main():
    blob_service = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    blob_client = blob_service.get_blob_client(CONTAINER, BLOB_NAME)
    assert blob_client.get_blob_properties().metadata == {"avscan": "ok"}

    result_queue = QueueClient.from_connection_string(CONNECTION_STRING, RESULT_QUEUE)
    messages = list(result_queue.receive_messages(messages_per_page=1))
    assert messages, "Expected a scan-result queue message"
    result = json.loads(messages[0].content)
    assert result["ScanError"] == ""
    assert result["UpdatedBlobMetadata"] == {"avscan": "ok"}

    print("✅ E2E Test Verification Successful: Blob metadata and queue result are correct!")

if __name__ == "__main__":
    main()
