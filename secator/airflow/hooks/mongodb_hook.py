"""Airflow Connection hook for secator's MongoDB.

Allows managing the MongoDB connection via Airflow's Connections UI
(Admin -> Connections) instead of hardcoding credentials in secator config.

Setup in Airflow UI:
    Connection Id:   secator_mongodb
    Connection Type: Generic  (or Mongo if mongo provider is installed)
    Host:            localhost
    Port:            27017
    Login:           (username, if auth enabled)
    Password:        (password, if auth enabled)

Usage::

    from secator.airflow.hooks.mongodb_hook import SecatorMongoDBHook

    hook = SecatorMongoDBHook()
    client = hook.get_client()
    db = client.main
    findings = db.findings.find({})
"""

import logging

from airflow.hooks.base import BaseHook

logger = logging.getLogger(__name__)


class SecatorMongoDBHook(BaseHook):
    """Airflow hook wrapping secator's MongoDB connection.

    Falls back to secator's native config (``CONFIG.addons.mongodb.url``)
    if no Airflow Connection is configured.
    """

    conn_name_attr = 'secator_mongodb_conn_id'
    default_conn_name = 'secator_mongodb'
    conn_type = 'generic'
    hook_name = 'Secator MongoDB'

    def __init__(self, conn_id='secator_mongodb'):
        super().__init__()
        self.conn_id = conn_id
        self._client = None

    def get_client(self):
        """Get or create a PyMongo client.

        Tries the Airflow Connection first; falls back to secator config.

        Returns:
            pymongo.MongoClient
        """
        if self._client is not None:
            return self._client

        import pymongo

        # Try Airflow Connection
        try:
            conn = self.get_connection(self.conn_id)
            if conn.host:
                uri = self._build_uri(conn)
                self._client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
                logger.info("MongoDB connected via Airflow Connection '%s'", self.conn_id)
                return self._client
        except Exception:
            logger.debug("Airflow Connection '%s' not found, falling back to secator config", self.conn_id)

        # Fall back to secator config
        from secator.hooks.mongodb import get_mongodb_client
        self._client = get_mongodb_client()
        return self._client

    @staticmethod
    def _build_uri(conn):
        """Build a MongoDB URI from an Airflow Connection object."""
        host = conn.host or 'localhost'
        port = conn.port or 27017
        if conn.login and conn.password:
            return f"mongodb://{conn.login}:{conn.password}@{host}:{port}"
        return f"mongodb://{host}:{port}"
