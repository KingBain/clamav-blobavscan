import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture
def scanner():
    module_path = Path(__file__).parents[2] / "clamav-blobavscan" / "scan_blob.py"
    spec = importlib.util.spec_from_file_location("scan_blob", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_get_config_uses_defaults_and_environment(scanner, monkeypatch):
    monkeypatch.delenv("queue_name", raising=False)
    assert scanner.get_config()["queue_name"] == "virus-scan"
    environment = {
        "STORAGE_ACCOUNT": "account",
        "CLIENT_ID": "client",
        "queue_name": "incoming",
        "result_queue_name": "results",
        "quarantine_container_name": "quarantine",
        "container_name": "source",
        "WORK_DIR": "/work",
        "ENABLE_QUARANTINE": "true",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    assert scanner.get_config() == {
        "STORAGE_ACCOUNT": "account",
        "CLIENT_ID": "client",
        "queue_name": "incoming",
        "result_queue_name": "results",
        "quarantine_container_name": "quarantine",
        "datahub_container_name": "source",
        "WORK_DIR": "/work",
        "ENABLE_QUARANTINE": "true",
    }


def test_initialize_clients_defers_azure_setup_until_requested(scanner, monkeypatch):
    credential = Mock()
    queue = Mock(side_effect=["input", "output"])
    monkeypatch.setattr(scanner, "DefaultAzureCredential", credential)
    monkeypatch.setattr(scanner, "QueueClient", queue)
    monkeypatch.setattr(scanner, "BlobServiceClient", Mock(return_value="blobs"))
    monkeypatch.setattr(scanner, "TableServiceClient", Mock(return_value="tables"))
    scanner.config = {"CLIENT_ID": "id", "STORAGE_ACCOUNT": "account", "queue_name": "q", "result_queue_name": "r"}

    scanner.initialize_clients()

    credential.assert_called_once_with(managed_identity_client_id="id")
    assert (scanner.queue_client, scanner.result_queue_client) == ("input", "output")
    assert scanner.blob_service_client == "blobs"
    assert scanner.table_service_client == "tables"


@pytest.mark.parametrize(
    ("result", "name", "expected"),
    [
        (None, "blob", []),
        ({"file": ("OK", "")}, "blob", []),
        ({"file": ("UNKNOWN", "details")}, "blob", []),
        ({"file": ("FOUND", "virus")}, "blob", ["virus"]),
        ({"file": ("OK", "")}, "clamavtest2025a", ["Testing...file name include clamavtest2025a"]),
    ],
)
def test_scan_blob_handles_clamav_results(scanner, result, name, expected):
    blob = Mock()
    blob.get_blob_properties.return_value = SimpleNamespace(size=1)
    blob.download_blob.return_value.readall.return_value = b"contents"
    clamav = Mock()
    clamav.scan_file.return_value = result

    assert scanner.scan_blob(blob, name, clamav) == expected


def test_scan_blob_scans_multiple_clean_chunks(scanner, monkeypatch):
    monkeypatch.setattr(scanner, "CHUNK_SIZE", 1)
    blob = Mock()
    blob.get_blob_properties.return_value = SimpleNamespace(size=2)
    blob.download_blob.return_value.readall.return_value = b"x"
    clamav = Mock()
    clamav.scan_file.return_value = {"file": ("OK", "")}

    assert scanner.scan_blob(blob, "blob", clamav) == []
    assert blob.download_blob.call_count == 2


def test_split_blob_path(scanner):
    assert scanner.split_blob_path("/events/blobServices/default/containers/datahub/blobs/a/b") == (
        "datahub",
        "a/b",
        "/datahub/a/b",
        "/events/blobServices/default/containers/datahub/blobs/a/b",
    )


def message(subject, url="https://example.test/blob"):
    return SimpleNamespace(
        content=base64.b64encode(json.dumps({"subject": subject, "data": {"blobUrl": url}}).encode())
    )


def configure_process(scanner, monkeypatch, scan_result, exists=True, quarantine=False):
    blob = Mock(url="https://example.test/source")
    blob.exists.return_value = exists
    blob.get_blob_properties.return_value = SimpleNamespace(metadata={})
    quarantine_blob = Mock()
    scanner.blob_service_client = Mock()
    scanner.blob_service_client.get_blob_client.side_effect = [blob, quarantine_blob]
    scanner.table_service_client = Mock()
    scanner.result_queue_client = Mock()
    scanner.config = {
        "datahub_container_name": "datahub",
        "quarantine_container_name": "quarantine",
        "ENABLE_QUARANTINE": str(quarantine).lower(),
    }
    monkeypatch.setattr(scanner, "scan_blob", Mock(return_value=scan_result))
    monkeypatch.setattr(scanner.pyclamd, "ClamdUnixSocket", Mock(return_value="socket"))
    return blob, quarantine_blob


def test_process_message_skips_unconfigured_container(scanner):
    scanner.config = {"datahub_container_name": "datahub"}
    scanner.blob_service_client = Mock()
    scanner.process_message(message("/events/blobServices/default/containers/other/blobs/a"))
    scanner.blob_service_client.get_blob_client.assert_not_called()


def test_process_message_skips_missing_blob(scanner, monkeypatch):
    blob, _ = configure_process(scanner, monkeypatch, [], exists=False)
    scanner.process_message(message("/events/blobServices/default/containers/datahub/blobs/a"))
    blob.set_blob_metadata.assert_not_called()


def test_process_message_records_clean_scan(scanner, monkeypatch):
    blob, _ = configure_process(scanner, monkeypatch, [])
    scanner.process_message(message("/events/blobServices/default/containers/datahub/blobs/a"))
    assert blob.set_blob_metadata.call_args.kwargs["metadata"] == {"avscan": "ok"}
    scanner.result_queue_client.send_message.assert_called_once()


def test_process_message_quarantines_infected_blob(scanner, monkeypatch):
    blob, quarantine_blob = configure_process(scanner, monkeypatch, ["virus"], quarantine=True)
    quarantine_blob.exists.return_value = True
    scanner.process_message(message("/events/blobServices/default/containers/datahub/blobs/a"))
    quarantine_blob.delete_blob.assert_called_once()
    quarantine_blob.start_copy_from_url.assert_called_once_with(blob.url)
    blob.delete_blob.assert_called_once()
    assert blob.set_blob_metadata.call_args.kwargs["metadata"] == {"avscan": "fail", "avscan_reason": '["virus"]'}


def test_process_message_preserves_metadata_when_table_write_fails(scanner, monkeypatch):
    blob, _ = configure_process(scanner, monkeypatch, ["virus"])
    scanner.table_service_client.get_table_client.return_value.create_entity.side_effect = RuntimeError("table")
    with pytest.raises(RuntimeError, match="table"):
        scanner.process_message(message("/events/blobServices/default/containers/datahub/blobs/a"))
    blob.set_blob_metadata.assert_not_called()


def test_main_deletes_successful_messages(scanner, monkeypatch):
    queue = Mock()
    queue.receive_messages.return_value.by_page.return_value = [["message"]]
    scanner.queue_client = queue
    monkeypatch.setattr(scanner, "initialize_clients", Mock())
    monkeypatch.setattr(scanner, "process_message", Mock())
    scanner.main()
    queue.delete_message.assert_called_once_with("message")


def test_main_retries_failed_messages(scanner, monkeypatch):
    queue = Mock()
    queue.receive_messages.return_value.by_page.return_value = [["message"]]
    scanner.queue_client = queue
    monkeypatch.setattr(scanner, "initialize_clients", Mock())
    monkeypatch.setattr(scanner, "process_message", Mock(side_effect=RuntimeError("scan")))
    scanner.main()
    queue.update_message.assert_called_once_with(message="message", visibility_timeout=28800)
