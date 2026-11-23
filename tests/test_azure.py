import pytest

from qci_infra.azure import Arm, AzureError


def test_token_never_sent_to_non_arm_host():
    with pytest.raises(AzureError, match="refusing non-ARM URL"):
        Arm().request("GET", "sub-1", "https://evil.example.com/next?page=2")
