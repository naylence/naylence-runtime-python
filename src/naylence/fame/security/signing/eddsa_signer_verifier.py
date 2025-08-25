from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Dict
from uuid import UUID

from pydantic import BaseModel

from naylence.fame.core.protocol.envelope import AllFramesUnion, FameEnvelope
from naylence.fame.util.logging import getLogger
from naylence.fame.util.util import secure_digest

logger = getLogger(__name__)


def _to_serialisable(obj: Any) -> Any:
    """
    Convert arbitrary Python objects into a JSON-friendly, canonical form.

    • bytes           -> base64 string (urlsafe, no padding)
    • datetime        -> ISO 8601 with microseconds, UTC/Z preserved
    • Decimal         -> canonical string without trailing zeros
    • Enum            -> its .value
    • UUID            -> str(uuid)
    • BaseModel       -> model_dump() result
    • set/tuple       -> list (order preserved for tuple, sorted for set)
    • Mapping / list  -> recurse
    • everything else -> untouched (must already be JSON primitive)
    """
    if obj is None or isinstance(obj, (str | int | float | bool)):
        return obj

    if isinstance(obj, bytes):
        return base64.urlsafe_b64encode(obj).rstrip(b"=").decode("ascii")

    if isinstance(obj, datetime):
        return obj.isoformat(timespec="microseconds")

    if isinstance(obj, Decimal):
        return format(obj.normalize(), "f")

    if isinstance(obj, Enum):
        return _to_serialisable(obj.value)

    if isinstance(obj, UUID):
        return str(obj)

    if isinstance(obj, BaseModel):
        return _to_serialisable(obj.model_dump(mode="python", exclude_none=True))

    if isinstance(obj, Mapping):
        return {k: _to_serialisable(v) for k, v in obj.items()}

    if isinstance(obj, tuple):
        return [_to_serialisable(i) for i in obj]  # keep order

    if isinstance(obj, set):
        return sorted(_to_serialisable(i) for i in obj)  # deterministic

    if isinstance(obj, Sequence):  # list, deque, …
        return [_to_serialisable(i) for i in obj]

    # Fallback – last resort
    return str(obj)


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        _to_serialisable(obj),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


def _remove_null_fields(obj: Any) -> Any:
    """Recursively remove null/None fields from a dictionary or list."""
    if isinstance(obj, dict):
        return {k: _remove_null_fields(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [_remove_null_fields(item) for item in obj if item is not None]
    else:
        return obj


def frame_digest(frame: AllFramesUnion) -> str:
    from naylence.fame.core.protocol.frames import DataFrame

    if isinstance(frame, DataFrame):
        # For DataFrame, only hash the payload for performance
        # All other frame fields are covered by the envelope signature
        if frame.payload is None:
            payload_str = ""
        else:
            # Use canonical JSON for consistent serialization
            payload_str = _canonical_json(frame.payload)
        # logger.trace("computed_dataframe_payload_digest", payload=payload_str)
        return secure_digest(payload_str)
    else:
        # For all other frame types, hash the entire frame
        # Get the frame data and ensure consistent null field handling
        frame_data = frame.model_dump(by_alias=True, exclude_none=True)
        # Remove any remaining null fields to ensure consistency

        cleaned_data = _remove_null_fields(frame_data)
        canon = _canonical_json(cleaned_data)
        # canon = _canonical_json(frame_data)

        # logger.trace("computed_frame_digest", digest=canon)
        return secure_digest(canon)


def immutable_headers(env: FameEnvelope) -> Dict[str, Any]:
    return {
        "version": env.version,
        "id": env.id,
        "sid": str(env.sid) if env.sid else None,
        "trace_id": env.trace_id,
        "to": str(env.to) if env.to else None,
        "reply_to": str(env.reply_to) if env.reply_to else None,
        "capabilities": env.capabilities,
        "corr_id": env.corr_id,
    }
