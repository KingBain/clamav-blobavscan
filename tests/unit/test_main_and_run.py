from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def test_create_result_message_handles_clean_and_infected_results(scanner_module):
    start = MagicMock()
    start.isoformat.return_value = "start"
    end = MagicMock()
    end.isoformat.return_value = "end"

    clean = scanner_module.create_result_message(
        blob_url="blob-url",
        scan_start_time=start,
        scan_end_time=end,
        scan_result=[],
        original_metadata={"before": "value"},
        updated_metadata={"avscan": "ok"},
    )

    infected = scanner_module.create_result_message(
        blob_url="blob-url",
        scan_start_time=start,
        scan_end_time=end,
        scan_result=["virus"],
        original_metadata={},
        updated_metadata={"avscan": "fail"},
    )

    assert clean["ScanError"] == ""
    assert infected["ScanError"] == '["virus"]'


def test_main_deletes_successes_and_requeues_failures(scanner_module):
    successful = SimpleNamespace(name="success")
    failed = SimpleNamespace(name="failed")
    pages = MagicMock()
    pages.by_page.return_value = [[successful, failed]]
    scanner_module.RUNTIME.queue_client = MagicMock()
    scanner_module.RUNTIME.queue_client.receive_messages.return_value = pages

    def process(message):
        if message is failed:
            raise RuntimeError("scan failed")

    scanner_module.main(process_function=process)

    scanner_module.RUNTIME.queue_client.receive_messages.assert_called_once_with(
        messages_per_page=10,
        visibility_timeout=14400,
    )
    scanner_module.RUNTIME.queue_client.delete_message.assert_called_once_with(successful)
    scanner_module.RUNTIME.queue_client.update_message.assert_called_once_with(
        message=failed,
        visibility_timeout=3600 * 8,
    )


def test_main_uses_default_process_function(scanner_module, monkeypatch):
    message = SimpleNamespace(name="message")
    pages = MagicMock()
    pages.by_page.return_value = [[message]]
    scanner_module.RUNTIME.queue_client = MagicMock()
    scanner_module.RUNTIME.queue_client.receive_messages.return_value = pages
    process_message = MagicMock()
    monkeypatch.setattr(scanner_module, "process_message", process_message)

    scanner_module.main()

    process_message.assert_called_once_with(message)
    scanner_module.RUNTIME.queue_client.delete_message.assert_called_once_with(message)


def test_main_requires_initialized_queue_client(scanner_module):
    with pytest.raises(RuntimeError, match="Queue client has not been initialized"):
        scanner_module.main()


def test_run_initializes_clients_and_starts_main(scanner_module, monkeypatch):
    app_config = {"STORAGE_ACCOUNT": "storage"}
    get_config = MagicMock(return_value=app_config)
    initialize_clients = MagicMock()
    main = MagicMock()
    monkeypatch.setattr(scanner_module, "get_config", get_config)
    monkeypatch.setattr(scanner_module, "initialize_clients", initialize_clients)
    monkeypatch.setattr(scanner_module, "main", main)

    scanner_module.run()

    get_config.assert_called_once_with()
    initialize_clients.assert_called_once_with(app_config)
    main.assert_called_once_with()
