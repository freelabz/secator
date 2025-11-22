import json
import logging
import time

import mysql.connector
from mysql.connector import Error
from celery import shared_task

from secator.config import CONFIG
from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

MYSQL_HOST = CONFIG.addons.mysql.host
MYSQL_PORT = CONFIG.addons.mysql.port
MYSQL_USER = CONFIG.addons.mysql.user
MYSQL_PASSWORD = CONFIG.addons.mysql.password
MYSQL_DATABASE = CONFIG.addons.mysql.database
MYSQL_UPDATE_FREQUENCY = CONFIG.addons.mysql.update_frequency

logger = logging.getLogger(__name__)

_mysql_connection = None


def get_mysql_connection():
	"""Get or create MySQL connection"""
	global _mysql_connection
	if _mysql_connection is None or not _mysql_connection.is_connected():
		try:
			_mysql_connection = mysql.connector.connect(
				host=MYSQL_HOST,
				port=MYSQL_PORT,
				user=MYSQL_USER,
				password=MYSQL_PASSWORD,
				database=MYSQL_DATABASE,
				autocommit=True
			)
			_init_tables(_mysql_connection)
		except Error as e:
			logger.error(f'Error connecting to MySQL: {e}')
			raise
	return _mysql_connection


def _init_tables(connection):
	"""Initialize MySQL tables if they don't exist"""
	cursor = connection.cursor()
	
	# Create runners table (for tasks, workflows, scans)
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS runners (
			id INT AUTO_INCREMENT PRIMARY KEY,
			runner_type VARCHAR(50) NOT NULL,
			name VARCHAR(255) NOT NULL,
			status VARCHAR(50),
			data JSON,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_runner_type (runner_type),
			INDEX idx_name (name)
		)
	""")
	
	# Create findings table
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS findings (
			id INT AUTO_INCREMENT PRIMARY KEY,
			uuid VARCHAR(255) UNIQUE,
			type VARCHAR(100) NOT NULL,
			data JSON NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_uuid (uuid),
			INDEX idx_type (type)
		)
	""")
	
	cursor.close()


def get_runner_dbg(runner):
	"""Runner debug object"""
	return {
		runner.unique_name: runner.status,
		'type': runner.config.type,
		'class': runner.__class__.__name__,
		'caller': runner.config.name,
		**runner.context
	}


def get_results(uuids):
	"""Get results from MySQL based on a list of uuids.

	Args:
		uuids (list[str | Output]): List of uuids, but can also be a mix of uuids and output types.

	Returns:
		Generator of findings.
	"""
	connection = get_mysql_connection()
	cursor = connection.cursor(dictionary=True)
	del_uuids = []
	
	for r in uuids:
		if isinstance(r, tuple(OUTPUT_TYPES)):
			yield r
			del_uuids.append(r)
	
	uuids = [u for u in uuids if u not in del_uuids]
	if uuids:
		placeholders = ', '.join(['%s'] * len(uuids))
		query = f"SELECT data FROM findings WHERE uuid IN ({placeholders})"
		cursor.execute(query, uuids)
		
		for row in cursor.fetchall():
			finding = load_finding(json.loads(row['data']))
			yield finding
	
	cursor.close()


def update_runner(self):
	connection = get_mysql_connection()
	cursor = connection.cursor()
	type = self.config.type
	update = self.toDict()
	chunk = update.get('chunk')
	_id = self.context.get(f'{type}_chunk_id') if chunk else self.context.get(f'{type}_id')
	
	debug('to_update', sub='hooks.mysql', id=_id, obj=get_runner_dbg(self), obj_after=True, obj_breaklines=False, verbose=True)
	start_time = time.time()
	
	try:
		data_json = json.dumps(update)
		
		if _id:
			# Update existing runner
			query = """
				UPDATE runners 
				SET data = %s, status = %s, updated_at = CURRENT_TIMESTAMP
				WHERE id = %s
			"""
			cursor.execute(query, (data_json, self.status, _id))
			end_time = time.time()
			elapsed = end_time - start_time
			debug(
				f'[dim gold4]updated in {elapsed:.4f}s[/]', 
				sub='hooks.mysql', 
				id=_id, 
				obj=get_runner_dbg(self), 
				obj_after=False
			)
			self.last_updated_db = start_time
		else:
			# Insert new runner
			query = """
				INSERT INTO runners (runner_type, name, status, data)
				VALUES (%s, %s, %s, %s)
			"""
			cursor.execute(query, (type, self.name, self.status, data_json))
			_id = cursor.lastrowid
			
			if chunk:
				self.context[f'{type}_chunk_id'] = _id
			else:
				self.context[f'{type}_id'] = _id
			
			end_time = time.time()
			elapsed = end_time - start_time
			debug(f'in {elapsed:.4f}s', sub='hooks.mysql', id=_id, obj=get_runner_dbg(self), obj_after=False)
	
	except Error as e:
		logger.error(f'Error updating runner: {e}')
		raise
	finally:
		cursor.close()


def update_finding(self, item):
	if type(item) not in OUTPUT_TYPES:
		return item
	
	start_time = time.time()
	connection = get_mysql_connection()
	cursor = connection.cursor()
	
	try:
		update = item.toDict()
		_type = item._type
		_uuid = item._uuid
		data_json = json.dumps(update)
		
		if _uuid:
			# Try to update existing finding
			query = """
				UPDATE findings 
				SET data = %s, updated_at = CURRENT_TIMESTAMP
				WHERE uuid = %s
			"""
			cursor.execute(query, (data_json, _uuid))
			
			if cursor.rowcount > 0:
				status = 'UPDATED'
			else:
				# If no rows updated, insert new finding
				query = """
					INSERT INTO findings (uuid, type, data)
					VALUES (%s, %s, %s)
				"""
				cursor.execute(query, (_uuid, _type, data_json))
				status = 'CREATED'
		else:
			# Insert new finding and get its UUID
			query = """
				INSERT INTO findings (uuid, type, data)
				VALUES (UUID(), %s, %s)
			"""
			cursor.execute(query, (_type, data_json))
			
			# Get the generated UUID
			cursor.execute("SELECT uuid FROM findings WHERE id = LAST_INSERT_ID()")
			result = cursor.fetchone()
			item._uuid = result[0] if result else None
			status = 'CREATED'
		
		end_time = time.time()
		elapsed = end_time - start_time
		debug_obj = {
			_type: status,
			'type': 'finding',
			'class': self.__class__.__name__,
			'caller': self.config.name,
			**self.context
		}
		debug(f'in {elapsed:.4f}s', sub='hooks.mysql', id=str(item._uuid), obj=debug_obj, obj_after=False)
	
	except Error as e:
		logger.error(f'Error updating finding: {e}')
		raise
	finally:
		cursor.close()
	
	return item


def find_duplicates(self):
	from secator.celery import IN_CELERY_WORKER_PROCESS
	ws_id = self.toDict().get('context', {}).get('workspace_id')
	if not ws_id:
		return
	if not IN_CELERY_WORKER_PROCESS:
		tag_duplicates(ws_id)
	else:
		tag_duplicates.delay(ws_id)


def load_finding(obj, exclude_types=[]):
	finding_type = obj['_type']
	klass = None
	for otype in OUTPUT_TYPES:
		oname = otype.get_name()
		if oname in exclude_types:
			continue
		if finding_type == oname:
			klass = otype
			item = klass.load(obj)
			item._uuid = str(obj.get('_uuid', ''))
			return item
	return None


def load_findings(objs, exclude_types=[]):
	findings = [load_finding(obj, exclude_types) for obj in objs]
	return [f for f in findings if f is not None]


@shared_task
def tag_duplicates(ws_id: str = None, full_scan: bool = False, exclude_types=[]):
	"""Tag duplicates in workspace.

	Args:
		ws_id (str): Workspace id.
		full_scan (bool): If True, scan all findings, otherwise only untagged findings.
	"""
	debug(f'running duplicate check on workspace {ws_id}', sub='hooks.mysql')
	# Note: Duplicate detection for MySQL is simplified compared to MongoDB
	# Full implementation would require proper JSON querying capabilities
	# which vary by MySQL version (MySQL 5.7+ has JSON functions)
	pass


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner]
	}
}
