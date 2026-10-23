import importlib.util

from botocore.exceptions import ClientError


def load_scanner():
    spec = importlib.util.spec_from_file_location("iam_scanner", "iam-scanner/scanner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_access_denied_is_actionable():
    scanner = load_scanner()

    class DeniedIAM:
        def get_paginator(self, _):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
                "ListUsers",
            )

    try:
        scanner.scan_iam(DeniedIAM())
    except scanner.IAMScanError as error:
        message = str(error)
    else:
        raise AssertionError("Expected IAMScanError")

    assert "iam:ListUsers" in message
    assert "read-only" in message
