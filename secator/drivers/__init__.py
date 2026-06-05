from secator.drivers._base import Driver  # noqa: F401

DRIVER_REGISTRY = {
	'api': ('secator.drivers.api', 'ApiDriver'),
	'discord': ('secator.drivers.discord', 'DiscordDriver'),
	'gcs': ('secator.drivers.gcs', 'GCSDriver'),
	'mongodb': ('secator.drivers.mongodb', 'MongoDBDriver'),
}

__all__ = ['Driver', 'DRIVER_REGISTRY']
