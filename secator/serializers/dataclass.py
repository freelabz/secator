from datetime import date, datetime
import json
from pathlib import PosixPath
from secator.output_types import OUTPUT_TYPES


class DataclassEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'toDict'):
            return obj.toDict()
        elif isinstance(obj, PosixPath):
            return str(obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)


def get_output_cls(type):
    try:
        return [cls for cls in OUTPUT_TYPES if cls.get_name() == type][0]
    except IndexError:
        return None


def dataclass_decoder(obj):
    if '_type' in obj:
        output_cls = get_output_cls(obj['_type'])
        if output_cls:
            return output_cls.load(obj)
    return obj


def dumps_dataclass(obj, indent=None):
    return json.dumps(obj, cls=DataclassEncoder, indent=indent)


def loads_dataclass(obj):
    return json.loads(obj, object_hook=dataclass_decoder)
