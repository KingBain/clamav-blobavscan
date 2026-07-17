from unittest.mock import MagicMock, call

import pytest


def test_get_config_uses_defaults(scanner_module, monkeypatch):
    for name in (
        "STORAGE_ACCOUNT",
        "STORAGE_CONNECTION_STRING",
        "CLIENT_ID",
        "queue_name",
        "result_queue_name",
        "quarantine_container_name",
        "container_name",
        "WORK_DIR",
        "ENABLE_QUARANTINE",
    ):
        monkeypatch.delenv(name, raising=False)

    assert scanner_module.get_config() == {
        "STORAGE_ACCOUNT": None,
        "STORAGE_CONNECTION_STRING": None,
        "CLIENT_ID": None,
        "queue_name": "virus-scan",
        "result_queue_name": "clamav-scan-result",
        "quarantine_container_name": "datahub-quarantine",
        "datahub_container_name": "datahub",
        "WORK_DIR": "/datahub-temp",
        "ENABLE_QUARANTINE": "false",
    }


def test_get_config_uses_environment_values(scanner_module, monkeypatch):
    values = {
        "STORAGE_ACCOUNT": "storage",
        "STORAGE_CONNECTION_STRING": "connection-string",
        "CLIENT_ID": "client-id",
        "queue_name": "incoming",
        "result_queue_name": "results",
        "quarantine_container_name": "quarantine",
        "container_name": "one,two",
        "WORK_DIR": "/tmp/scans",
        "ENABLE_QUARANTINE": "true",
    }

    for name, value in values.items():
        monkeypatch.setenv(name, value)

    assert scanner_module.get_config() == {
        "STORAGE_ACCOUNT": "storage",
        "STORAGE_CONNECTION_STRING": "connection-string",
        "CLIENT_ID": "client-id",
        "queue_name": "incoming",
        "result_queue_name": "results",
        "quarantine_container_name": "quarantine",
        "datahub_container_name": "one,two",
        "WORK_DIR": "/tmp/scans",
        "ENABLE_QUARANTINE": "true",
    }


def test_initialize_clients_requires_storage_configuration(scanner_module):
    with pytest.raises(ValueError, match="STORAGE_ACCOUNT or STORAGE_CONNECTION_STRING is required"):
        scanner_module.initialize_clients({"STORAGE_ACCOUNT": None})


def test_initialize_clients_uses_connection_string_for_local_storage(scanner_module, monkeypatch):
    queue_from_connection_string = MagicMock(side_effect=["input-queue", "result-queue"])
    blob_from_connection_string = MagicMock(return_value="blob-service")
    table_from_connection_string = MagicMock(return_value="table-service")
    monkeypatch.setattr(scanner_module.QueueClient, "from_connection_string", queue_from_connection_string)
    monkeypatch.setattr(scanner_module.BlobServiceClient, "from_connection_string", blob_from_connection_string)
    monkeypatch.setattr(scanner_module.TableServiceClient, "from_connection_string", table_from_connection_string)
    config = {
        "STORAGE_ACCOUNT": None,
        "STORAGE_CONNECTION_STRING": "UseDevelopmentStorage=true",
        "queue_name": "input",
        "result_queue_name": "result",
    }

    scanner_module.initialize_clients(config)

    assert queue_from_connection_string.call_args_list == [
        call("UseDevelopmentStorage=true", queue_name="input"),
        call("UseDevelopmentStorage=true", queue_name="result"),
    ]
    blob_from_connection_string.assert_called_once_with("UseDevelopmentStorage=true")
    table_from_connection_string.assert_called_once_with("UseDevelopmentStorage=true")
    assert scanner_module.RUNTIME.config == config


def test_initialize_clients_creates_expected_clients(scanner_module, monkeypatch):
    credential = object()
    default_credential = MagicMock(return_value=credential)
    queue_constructor = MagicMock(side_effect=["input-queue", "result-queue"])
    blob_constructor = MagicMock(return_value="blob-service")
    table_constructor = MagicMock(return_value="table-service")

    monkeypatch.setattr(scanner_module, "DefaultAzureCredential", default_credential)
    monkeypatch.setattr(scanner_module, "QueueClient", queue_constructor)
    monkeypatch.setattr(scanner_module, "BlobServiceClient", blob_constructor)
    monkeypatch.setattr(scanner_module, "TableServiceClient", table_constructor)

    app_config = {
        "STORAGE_ACCOUNT": "storage",
        "CLIENT_ID": "client-id",
        "queue_name": "incoming",
        "result_queue_name": "results",
    }

    scanner_module.initialize_clients(app_config)

    default_credential.assert_called_once_with(managed_identity_client_id="client-id")
    assert queue_constructor.call_count == 2
    queue_constructor.assert_any_call(
        account_url="https://storage.queue.core.windows.net/",
        queue_name="incoming",
        credential=credential,
    )
    queue_constructor.assert_any_call(
        account_url="https://storage.queue.core.windows.net/",
        queue_name="results",
        credential=credential,
    )
    blob_constructor.assert_called_once_with(
        account_url="https://storage.blob.core.windows.net/",
        credential=credential,
    )
    table_constructor.assert_called_once_with(
        endpoint="https://storage.table.core.windows.net/",
        credential=credential,
    )
    assert scanner_module.RUNTIME.config is app_config
    assert scanner_module.RUNTIME.queue_client == "input-queue"
    assert scanner_module.RUNTIME.result_queue_client == "result-queue"
    assert scanner_module.RUNTIME.blob_service_client == "blob-service"
    assert scanner_module.RUNTIME.table_service_client == "table-service"
