from unittest.mock import Mock

import pytest


@pytest.fixture(scope="class")
def setup_config(request):
    """
    Setup configuration for class method
    Create fake pycti OpenCTI helper
    """
    request.cls.mock_helper = Mock()

    yield
