from __future__ import annotations

import base64
import fnmatch
import hashlib
import inspect
import json
import re
from datetime import datetime
from functools import lru_cache
from typing import Any, Optional

from pydantic import BaseModel

from naylence.fame.core import DataFrame
from naylence.fame.factory import ExpressionEvaluationPolicy


def default_json_encoder(obj):
    if isinstance(obj, datetime):
        return obj.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def capitalize_first_letter(text: str) -> str:
    if not text:
        return text
    return text[0].upper() + text[1:]


def json_dumps(value: Any) -> str:
    return json.dumps(value, indent=2, default=default_json_encoder)


def pretty_model(model: BaseModel, safe_log: bool = True):
    # TODO: tmp
    safe_log = False
    return model.model_dump_json(context={"safe_log": safe_log}, indent=2, by_alias=True, exclude_none=True)


def extract_id(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        return obj.get("id")
    return getattr(obj, "id", None)


async def maybe_await(value_or_coroutine):
    if inspect.isawaitable(value_or_coroutine):
        return await value_or_coroutine
    return value_or_coroutine


def base_model_to_bytes(message: BaseModel) -> bytes:
    json_string = message.model_dump_json(by_alias=True, exclude_none=True)
    return json_string.encode("utf-8")


def decode_fame_data_payload(frame: DataFrame) -> Any:
    if frame.codec == "b64":
        payload_bytes = base64.b64decode(frame.payload)
        return payload_bytes
    return frame.payload


def normalize_path(path: str):
    return path.lstrip("/")


@lru_cache(maxsize=256)
def compiled_path_pattern(pattern: str) -> re.Pattern[str]:
    """
    Translate a shell-style wildcard pattern into a compiled regex
    and cache the result for speed.
    """
    return re.compile(fnmatch.translate(pattern))


# 0–9, a–z, A–Z
_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _to_base62(num: int) -> str:
    if num == 0:
        return _BASE62[0]
    out = []
    while num > 0:
        num, rem = divmod(num, 62)
        out.append(_BASE62[rem])
    return "".join(reversed(out))


def secure_digest(s: str, bits: int = 128) -> str:
    """
    - s: input string
    - bits: how many bits of digest to include (e.g. 128 or 64)
    Returns a base62 string.
    """
    # 1. Full SHA256 digest
    full = hashlib.sha256(s.encode("utf-8")).digest()
    # 2. Truncate to desired bits
    nbytes = bits // 8
    truncated = full[:nbytes]
    # 3. Big-endian integer
    val = int.from_bytes(truncated, "big")
    # 4. Base-62 encode
    return _to_base62(val)


def urlsafe_base64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def deserialize_model(
    model_class,
    config,
    expression_evaluation_policy: Optional[ExpressionEvaluationPolicy] = ExpressionEvaluationPolicy.ERROR,
):
    return model_class.model_validate(
        config,
        context={"expression_evaluation_policy": expression_evaluation_policy},
    )


def camel_to_snake_case(name: str) -> str:
    """Convert CamelCase string to snake_case."""
    # Insert underscore before uppercase letters that follow lowercase letters or digits
    s1 = re.sub("([a-z0-9])([A-Z])", r"\1_\2", name)
    # Insert underscore before uppercase letters that are followed by lowercase letters
    s2 = re.sub("([A-Z])([A-Z][a-z])", r"\1_\2", s1)
    return s2.lower()
