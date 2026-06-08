from secator.drivers.api import ApiDriver, get_runner_dbg, _make_request as _api_make_request  # noqa: F401

_driver = ApiDriver()
HOOKS = _driver.hooks


def _make_request(method, endpoint, data=None):
	"""Module-level wrapper for backward compatibility."""
	return _api_make_request(
		method, endpoint, data=data,
		api_url=_driver.url,
		api_key=_driver.api_key,
		api_header_name=_driver.header_name,
		force_ssl=_driver.force_ssl,
		api_timeout=_driver.timeout,
	)


def get_workspace_name(workspace_id):
	"""Module-level wrapper for backward compatibility."""
	return _driver.get_workspace_name(workspace_id)
