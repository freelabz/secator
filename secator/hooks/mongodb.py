from secator.drivers.mongodb import (  # noqa: F401
	MongoDBDriver,
	get_mongodb_client,
	get_results,
	load_finding,
	load_findings,
	tag_duplicates,
)

_driver = MongoDBDriver()
HOOKS = _driver.hooks
