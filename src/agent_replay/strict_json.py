"""Strict, dependency-free JSON boundary shared by core and adapters."""
import json
import math


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"non-finite JSON value is not permitted: {value}")


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        _constant(value)
    return result


def loads(value, **kwargs):
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)


def load(stream, **kwargs):
    return loads(stream.read())


def dumps(value, **kwargs):
    return json.dumps(value, **{**kwargs, "allow_nan": False})


def dump(value, stream, **kwargs):
    stream.write(dumps(value, **kwargs))
