import json
from dataclasses import dataclass, asdict
from secsy.output_types import OutputType


class DataclassEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, OutputType):
            return json.dumps(asdict(obj))
        else:
            return json.JSONEncoder.default(self, obj)


def my_decoder(obj):
    if '_type' in obj:
        return OutputType.load(obj)
    return obj


def my_dumps(obj):
    return json.dumps(obj, cls=DataclassEncoder)


def my_loads(obj):
    return json.loads(obj, object_hook=my_decoder)