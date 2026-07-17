import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def make_message(container="datahub", blob="file.txt"):
    event = {
        "subject": ("/blobServices/default/containers/" f"{container}/blobs/{blob}"),
        "data": {"blobUrl": ("https://storage.blob.core.windows.net/" f"{container}/{blob}")},
    }
    return SimpleNamespace(content=base64.b64encode(json.dumps(event).encode()).decode())


def make_config(**overrides):
    config = {
        "datahub_container_name": "datahub",
        "quarantine_container_name": "quarantine",
        "WORK_DIR": "/datahub-temp",
        "ENABLE_QUARANTINE": "false",
    }
    config.update(overrides)
    return config


def configure_blob(scanner_module, metadata=None, exists=True):
    blob_client = MagicMock()
    blob_client.exists.return_value = exists
    blob_client.url = "https://storage.blob.core.windows.net/datahub/file.txt"
    blob_client.get_blob_properties.return_value = SimpleNamespace(metadata=metadata)
    scanner_module.RUNTIME.blob_service_client = MagicMock()
    scanner_module.RUNTIME.blob_service_client.get_blob_client.return_value = blob_client
    return blob_client


def test_process_message_requires_initialized_config(scanner_module):
    with pytest.raises(RuntimeError, match="has not been initialized"):
        scanner_module.process_message(make_message())


def test_process_message_uses_module_config(scanner_module, monkeypatch):
    scanner_module.RUNTIME.config = make_config()
    blob_client = configure_blob(scanner_module, metadata={})
    scanner_module.RUNTIME.result_queue_client = MagicMock()
    monkeypatch.setattr(scanner_module.pyclamd, "ClamdUnixSocket", MagicMock())
    monkeypatch.setattr(scanner_module, "scan_blob", MagicMock(return_value=[]))

    result = scanner_module.process_message(make_message())

    assert result["UpdatedBlobMetadata"] == {"avscan": "ok"}
    blob_client.set_blob_metadata.assert_called_once_with(metadata={"avscan": "ok"})


def test_process_message_skips_unconfigured_container(scanner_module):
    scanner_module.RUNTIME.blob_service_client = MagicMock()

    result = scanner_module.process_message(
        make_message(container="other"),
        app_config=make_config(datahub_container_name="one, DATAHUB "),
    )

    assert result is None
    scanner_module.RUNTIME.blob_service_client.get_blob_client.assert_not_called()


def test_process_message_returns_when_blob_is_missing(scanner_module):
    blob_client = configure_blob(scanner_module, exists=False)

    result = scanner_module.process_message(
        make_message(),
        app_config=make_config(),
    )

    assert result is None
    blob_client.get_blob_properties.assert_not_called()


def test_process_message_requires_initialized_blob_service_client(scanner_module):
    with pytest.raises(RuntimeError, match="Blob service client has not been initialized"):
        scanner_module.process_message(make_message(), app_config=make_config())


def test_process_message_handles_clean_file(scanner_module, monkeypatch):
    original = {
        "uploadedby": "john@example.ca",
        "avscan_reason": "old value",
    }
    blob_client = configure_blob(scanner_module, metadata=original)
    scanner_module.RUNTIME.result_queue_client = MagicMock()
    clamav_socket = object()
    monkeypatch.setattr(
        scanner_module.pyclamd,
        "ClamdUnixSocket",
        MagicMock(return_value=clamav_socket),
    )
    scan = MagicMock(return_value=[])
    monkeypatch.setattr(scanner_module, "scan_blob", scan)

    result = scanner_module.process_message(
        make_message(),
        app_config=make_config(),
    )

    scan.assert_called_once_with(
        blob_client,
        "/blobServices/default/containers/datahub/blobs/file.txt",
        clamav_socket,
        work_dir="/datahub-temp",
    )
    assert result["ScanError"] == ""
    assert result["OriginalBlobMetadata"] == original
    assert result["UpdatedBlobMetadata"] == {
        "uploadedby": "john@example.ca",
        "avscan": "ok",
    }
    blob_client.set_blob_metadata.assert_called_once_with(metadata=result["UpdatedBlobMetadata"])
    sent = json.loads(scanner_module.RUNTIME.result_queue_client.send_message.call_args.args[0])
    assert sent == result


def test_process_message_handles_none_metadata(scanner_module, monkeypatch):
    blob_client = configure_blob(scanner_module, metadata=None)
    scanner_module.RUNTIME.result_queue_client = MagicMock()
    monkeypatch.setattr(scanner_module.pyclamd, "ClamdUnixSocket", MagicMock())
    monkeypatch.setattr(scanner_module, "scan_blob", MagicMock(return_value=[]))

    result = scanner_module.process_message(
        make_message(),
        app_config=make_config(),
    )

    assert result["OriginalBlobMetadata"] == {}
    assert result["UpdatedBlobMetadata"] == {"avscan": "ok"}
    blob_client.set_blob_metadata.assert_called_once_with(metadata={"avscan": "ok"})


def test_process_message_requires_initialized_result_queue_client(scanner_module, monkeypatch):
    blob_client = configure_blob(scanner_module, metadata={})
    monkeypatch.setattr(scanner_module.pyclamd, "ClamdUnixSocket", MagicMock())
    monkeypatch.setattr(scanner_module, "scan_blob", MagicMock(return_value=[]))

    with pytest.raises(RuntimeError, match="Result queue client has not been initialized"):
        scanner_module.process_message(make_message(), app_config=make_config())

    blob_client.set_blob_metadata.assert_called_once_with(metadata={"avscan": "ok"})


def test_process_message_handles_infected_file_without_quarantine(
    scanner_module,
    monkeypatch,
):
    blob_client = configure_blob(
        scanner_module,
        metadata={"uploadedby": "john@example.ca"},
    )
    scanner_module.RUNTIME.result_queue_client = MagicMock()
    monkeypatch.setattr(scanner_module.pyclamd, "ClamdUnixSocket", MagicMock())
    monkeypatch.setattr(
        scanner_module,
        "scan_blob",
        MagicMock(return_value=["Eicar-Signature"]),
    )
    record = MagicMock()
    move = MagicMock()
    monkeypatch.setattr(scanner_module, "record_infected_file", record)
    monkeypatch.setattr(scanner_module, "move_blob_to_quarantine", move)

    result = scanner_module.process_message(
        make_message(),
        app_config=make_config(ENABLE_QUARANTINE="false"),
    )

    expected_metadata = {
        "uploadedby": "john@example.ca",
        "avscan": "fail",
        "avscan_reason": '["Eicar-Signature"]',
    }
    record.assert_called_once_with(
        "/datahub/file.txt",
        ["Eicar-Signature"],
    )
    move.assert_not_called()
    blob_client.set_blob_metadata.assert_called_once_with(metadata=expected_metadata)
    assert result["ScanError"] == '["Eicar-Signature"]'
    assert result["UpdatedBlobMetadata"] == expected_metadata


def test_process_message_handles_infected_file_with_quarantine(
    scanner_module,
    monkeypatch,
):
    blob_client = configure_blob(scanner_module, metadata={})
    scanner_module.RUNTIME.result_queue_client = MagicMock()
    monkeypatch.setattr(scanner_module.pyclamd, "ClamdUnixSocket", MagicMock())
    monkeypatch.setattr(
        scanner_module,
        "scan_blob",
        MagicMock(return_value=["Eicar-Signature"]),
    )
    monkeypatch.setattr(scanner_module, "record_infected_file", MagicMock())
    move = MagicMock()
    monkeypatch.setattr(scanner_module, "move_blob_to_quarantine", move)
    config = make_config(ENABLE_QUARANTINE="TRUE")

    result = scanner_module.process_message(
        make_message(blob="folder/file.txt"),
        app_config=config,
    )

    move.assert_called_once_with(
        source_blob_client=blob_client,
        source_container="datahub",
        source_blob_name="folder/file.txt",
        updated_metadata={
            "avscan": "fail",
            "avscan_reason": '["Eicar-Signature"]',
        },
        app_config=config,
    )
    blob_client.set_blob_metadata.assert_not_called()
    assert result["UpdatedBlobMetadata"]["avscan"] == "fail"
