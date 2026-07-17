from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def test_split_blob_path_returns_expected_parts(scanner_module):
    subject = "/blobServices/default/containers/" "datahub/blobs/folder/file.txt"

    assert scanner_module.split_blob_path(subject) == (
        "datahub",
        "folder/file.txt",
        "/datahub/folder/file.txt",
        subject,
    )


@pytest.mark.parametrize(
    "subject",
    [
        "/invalid/path",
        "/blobServices/default/wrong/datahub/blobs/file.txt",
        "/blobServices/default/containers/datahub/wrong/file.txt",
    ],
)
def test_split_blob_path_rejects_invalid_structure(scanner_module, subject):
    with pytest.raises(ValueError, match="Invalid Azure Blob Storage"):
        scanner_module.split_blob_path(subject)


def test_split_blob_path_rejects_empty_container(scanner_module):
    subject = "/blobServices/default/containers//blobs/file.txt"

    with pytest.raises(ValueError, match="Invalid Azure Blob Storage"):
        scanner_module.split_blob_path(subject)


def test_get_copy_status_handles_none_dict_and_object(scanner_module):
    assert scanner_module.get_copy_status(None) == (None, None)
    assert scanner_module.get_copy_status({"status": "failed", "status_description": "bad"}) == ("failed", "bad")
    assert scanner_module.get_copy_status(SimpleNamespace(status="success", status_description=None)) == (
        "success",
        None,
    )


def test_wait_for_copy_completion_waits_then_succeeds(scanner_module, monkeypatch):
    client = MagicMock()
    client.get_blob_properties.side_effect = [
        SimpleNamespace(copy=SimpleNamespace(status="pending")),
        SimpleNamespace(copy=SimpleNamespace(status="success")),
    ]

    monotonic = MagicMock(side_effect=[0, 1, 2])
    sleep = MagicMock()
    monkeypatch.setattr(scanner_module.time, "monotonic", monotonic)
    monkeypatch.setattr(scanner_module.time, "sleep", sleep)

    scanner_module.wait_for_copy_completion(client)

    sleep.assert_called_once_with(scanner_module.COPY_POLL_INTERVAL_SECONDS)


@pytest.mark.parametrize("status", ["failed", "aborted"])
def test_wait_for_copy_completion_raises_for_failed_copy(
    scanner_module,
    monkeypatch,
    status,
):
    client = MagicMock()
    client.get_blob_properties.return_value = SimpleNamespace(
        copy={"status": status, "status_description": "copy problem"}
    )
    monkeypatch.setattr(scanner_module.time, "monotonic", MagicMock(return_value=0))

    with pytest.raises(RuntimeError, match=f"Blob copy {status}: copy problem"):
        scanner_module.wait_for_copy_completion(client)


def test_wait_for_copy_completion_uses_default_error_description(
    scanner_module,
    monkeypatch,
):
    client = MagicMock()
    client.get_blob_properties.return_value = SimpleNamespace(copy={"status": "failed", "status_description": ""})
    monkeypatch.setattr(scanner_module.time, "monotonic", MagicMock(return_value=0))

    with pytest.raises(RuntimeError, match="no details available"):
        scanner_module.wait_for_copy_completion(client)


def test_wait_for_copy_completion_times_out(scanner_module, monkeypatch):
    client = MagicMock()
    client.get_blob_properties.return_value = SimpleNamespace(copy=SimpleNamespace(status="pending"))
    monkeypatch.setattr(
        scanner_module.time,
        "monotonic",
        MagicMock(side_effect=[0, scanner_module.COPY_TIMEOUT_SECONDS]),
    )

    with pytest.raises(TimeoutError, match="did not finish"):
        scanner_module.wait_for_copy_completion(client)


def test_record_infected_file_creates_expected_entity(scanner_module, monkeypatch):
    table_client = MagicMock()
    scanner_module.table_service_client = MagicMock()
    scanner_module.table_service_client.get_table_client.return_value = table_client

    fake_now = MagicMock()
    fake_now.now.return_value.isoformat.return_value = "2026-07-17T12:00:00"
    monkeypatch.setattr(scanner_module, "datetime", fake_now)

    scanner_module.record_infected_file(
        "/datahub/eicar.txt",
        ["Eicar-Signature"],
    )

    scanner_module.table_service_client.get_table_client.assert_called_once_with(table_name="infectedfiles")
    table_client.create_entity.assert_called_once_with(
        entity={
            "PartitionKey": "|||datahub|||eicar.txt",
            "RowKey": "2026-07-17T12:00:00Z",
            "fileName": "/datahub/eicar.txt",
            "threats": '["Eicar-Signature"]',
        }
    )


def test_move_blob_to_quarantine_replaces_existing_blob(scanner_module, monkeypatch):
    source = MagicMock()
    source.url = "https://storage/datahub/eicar.txt"
    quarantine = MagicMock()
    quarantine.exists.return_value = True
    scanner_module.blob_service_client = MagicMock()
    scanner_module.blob_service_client.get_blob_client.return_value = quarantine
    wait_for_copy = MagicMock()
    monkeypatch.setattr(scanner_module, "wait_for_copy_completion", wait_for_copy)

    metadata = {"avscan": "fail"}
    config = {"quarantine_container_name": "quarantine"}

    scanner_module.move_blob_to_quarantine(
        source,
        "datahub",
        "folder/eicar.txt",
        metadata,
        config,
    )

    scanner_module.blob_service_client.get_blob_client.assert_called_once_with(
        container="quarantine",
        blob="datahub/folder/eicar.txt",
    )
    quarantine.delete_blob.assert_called_once_with()
    quarantine.start_copy_from_url.assert_called_once_with(source.url)
    wait_for_copy.assert_called_once_with(quarantine)
    quarantine.set_blob_metadata.assert_called_once_with(metadata=metadata)
    source.delete_blob.assert_called_once_with()


def test_move_blob_to_quarantine_does_not_delete_missing_destination(
    scanner_module,
    monkeypatch,
):
    source = MagicMock()
    source.url = "source-url"
    quarantine = MagicMock()
    quarantine.exists.return_value = False
    scanner_module.blob_service_client = MagicMock()
    scanner_module.blob_service_client.get_blob_client.return_value = quarantine
    monkeypatch.setattr(scanner_module, "wait_for_copy_completion", MagicMock())

    scanner_module.move_blob_to_quarantine(
        source,
        "datahub",
        "file.txt",
        {"avscan": "fail"},
        {"quarantine_container_name": "quarantine"},
    )

    quarantine.delete_blob.assert_not_called()
