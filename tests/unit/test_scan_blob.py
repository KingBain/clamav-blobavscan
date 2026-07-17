from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest


def make_download(content):
    download = MagicMock()
    download.readall.return_value = content
    return download


def test_scan_blob_rejects_invalid_chunk_size(scanner_module):
    with pytest.raises(ValueError, match="greater than zero"):
        scanner_module.scan_blob(
            MagicMock(),
            "/datahub/file.txt",
            MagicMock(),
            chunk_size=0,
        )


def test_scan_blob_handles_zero_byte_blob(scanner_module):
    blob_client = MagicMock()
    blob_client.get_blob_properties.return_value = SimpleNamespace(size=0)

    result = scanner_module.scan_blob(
        blob_client,
        "/datahub/empty.txt",
        MagicMock(),
        chunk_size=4,
    )

    assert result == []
    blob_client.download_blob.assert_not_called()


def test_scan_blob_handles_none_result(scanner_module, tmp_path):
    blob_client = MagicMock()
    blob_client.get_blob_properties.return_value = SimpleNamespace(size=4)
    blob_client.download_blob.return_value = make_download(b"clean")

    clamav_socket = MagicMock()
    clamav_socket.scan_file.return_value = None

    result = scanner_module.scan_blob(
        blob_client,
        "/datahub/clean.txt",
        clamav_socket,
        chunk_size=4,
        work_dir=str(tmp_path),
    )

    assert result == []
    blob_client.download_blob.assert_called_once_with(offset=0, length=4)


def test_scan_blob_handles_ok_and_unexpected_statuses(scanner_module, tmp_path):
    blob_client = MagicMock()
    blob_client.get_blob_properties.return_value = SimpleNamespace(size=4)
    blob_client.download_blob.return_value = make_download(b"data")

    clamav_socket = MagicMock()
    clamav_socket.scan_file.side_effect = lambda path: {
        path: ("OK", ""),
        "second": ("ERROR", "scanner error"),
    }

    result = scanner_module.scan_blob(
        blob_client,
        "/datahub/file.txt",
        clamav_socket,
        chunk_size=4,
        work_dir=str(tmp_path),
    )

    assert result == []


def test_scan_blob_returns_threat_and_stops_after_infected_chunk(
    scanner_module,
    tmp_path,
):
    blob_client = MagicMock()
    blob_client.get_blob_properties.return_value = SimpleNamespace(size=8)
    blob_client.download_blob.side_effect = [
        make_download(b"bad!"),
        make_download(b"next"),
    ]

    clamav_socket = MagicMock()
    clamav_socket.scan_file.side_effect = lambda path: {
        path: ("FOUND", "Eicar-Signature")
    }

    result = scanner_module.scan_blob(
        blob_client,
        "/datahub/eicar.txt",
        clamav_socket,
        chunk_size=4,
        work_dir=str(tmp_path),
    )

    assert result == ["Eicar-Signature"]
    blob_client.download_blob.assert_called_once_with(offset=0, length=4)


def test_scan_blob_downloads_multiple_clean_chunks(scanner_module, tmp_path):
    blob_client = MagicMock()
    blob_client.get_blob_properties.return_value = SimpleNamespace(size=10)
    blob_client.download_blob.side_effect = [
        make_download(b"abcd"),
        make_download(b"efgh"),
        make_download(b"ij"),
    ]

    clamav_socket = MagicMock()
    clamav_socket.scan_file.return_value = None

    result = scanner_module.scan_blob(
        blob_client,
        "/datahub/multiple.txt",
        clamav_socket,
        chunk_size=4,
        work_dir=str(tmp_path),
    )

    assert result == []
    assert blob_client.download_blob.call_args_list == [
        call(offset=0, length=4),
        call(offset=4, length=4),
        call(offset=8, length=2),
    ]
