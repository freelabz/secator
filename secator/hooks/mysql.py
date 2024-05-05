import logging
import time

import mysql.connector
from mysql.connector import Error

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

MYSQL_CONFIG = CONFIG.addons.mysql

logger = logging.getLogger(__name__)

def connect_to_mysql():
    try:
        connection = mysql.connector.connect(
            host=MYSQL_CONFIG.host,
            port=MYSQL_CONFIG.port,
            database=MYSQL_CONFIG.database,
            user=MYSQL_CONFIG.user,
            password=MYSQL_CONFIG.password
        )
        if connection.is_connected():
            logger.info("Connected to MySQL database")
            return connection
        else:
            logger.error("Failed to connect to MySQL database")
            return None
    except Error as e:
        logger.error(f"Error connecting to MySQL database: {e}")
        return None

MYSQL_CONNECTION = connect_to_mysql()

def update_runner(self):
    if not MYSQL_CONNECTION:
        logger.error("MySQL connection not established. Unable to update runner.")
        return

    cursor = MYSQL_CONNECTION.cursor()

    type = self.config.type
    table = f'{type}s'
    update = self.toDict()

    debug_obj = {'type': 'runner', 'name': self.name, 'status': self.status}

    query = f"UPDATE {table} SET "
    query += ", ".join([f"{key} = '{update[key]}'" for key in update])
    query += f" WHERE id = '{self.id}'"

    try:
        cursor.execute(query)
        MYSQL_CONNECTION.commit()
        logger.info("Runner updated successfully")
    except Error as e:
        logger.error(f"Error updating runner: {e}")
        MYSQL_CONNECTION.rollback()
    finally:
        cursor.close()

def update_finding(self, item):
    if not MYSQL_CONNECTION:
        logger.error("MySQL connection not established. Unable to update finding.")
        return item

    cursor = MYSQL_CONNECTION.cursor()

    update = item.toDict()

    query = "UPDATE findings SET "
    query += ", ".join([f"{key} = '{update[key]}'" for key in update])
    query += f" WHERE id = '{item.id}'"

    try:
        cursor.execute(query)
        MYSQL_CONNECTION.commit()
        logger.info("Finding updated successfully")
    except Error as e:
        logger.error(f"Error updating finding: {e}")
        MYSQL_CONNECTION.rollback()
    finally:
        cursor.close()

    return item

def tag_duplicates(ws_id):
    if not MYSQL_CONNECTION:
        logger.error("MySQL connection not established. Unable to tag duplicates.")
        return

    cursor = MYSQL_CONNECTION.cursor()

    workspace_query = f"SELECT * FROM findings WHERE workspace_id = '{ws_id}' AND tagged = True ORDER BY timestamp DESC"
    untagged_query = f"SELECT * FROM findings WHERE workspace_id = '{ws_id}' ORDER BY timestamp DESC"

    try:
        cursor.execute(workspace_query)
        workspace_findings = cursor.fetchall()
        cursor.execute(untagged_query)
        untagged_findings = cursor.fetchall()

        # Your duplicate checking logic here
        
        MYSQL_CONNECTION.commit()
        logger.info("Duplicates tagged successfully")
    except Error as e:
        logger.error(f"Error tagging duplicates: {e}")
        MYSQL_CONNECTION.rollback()
    finally:
        cursor.close()

MYSQL_HOOKS = {
    Scan: {
        'on_start': [update_runner],
        'on_iter': [update_runner],
        'on_duplicate': [update_finding],
        'on_end': [update_runner],
    },
    Workflow: {
        'on_start': [update_runner],
        'on_iter': [update_runner],
        'on_duplicate': [update_finding],
        'on_end': [update_runner],
    },
    Task: {
        'on_init': [update_runner],
        'on_start': [update_runner],
        'on_item': [update_finding],
        'on_duplicate': [update_finding],
        'on_iter': [update_runner],
        'on_end': [update_runner]
    }
}
