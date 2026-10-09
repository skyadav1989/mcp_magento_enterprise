from app.services.url_validator import validate_magento_url
import pytest

def test_invalid_url():
    with pytest.raises(ValueError):
        import asyncio
        asyncio.run(validate_magento_url('not-a-url'))
