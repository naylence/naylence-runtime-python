from __future__ import annotations

import json
from typing import List, Optional

import aiohttp

from naylence.fame.core import (
    FameEnvelope,
    FameEnvelopeWith,
    NodeHelloFrame,
    NodeWelcomeFrame,
)
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.security.auth.auth_injection_strategy import AuthInjectionStrategy


class WelcomeServiceClient(AdmissionClient):
    """
    HTTP-based implementation of FameAdmissionClient.
    Uses aiohttp to POST a NodeHelloFrame and parse a NodeWelcomeFrame.
    """

    def __init__(
        self,
        has_upstream: bool,
        url: str,
        supported_transports: List[str],
        session: Optional[aiohttp.ClientSession] = None,
        auth_strategy: Optional[AuthInjectionStrategy] = None,
    ):
        self._has_upstream = has_upstream
        self._url = url
        self._supported_transports = supported_transports
        self._session = session
        self._auth_strategy = auth_strategy
        self._auth_headers: dict[str, str] = {}

    @property
    def has_upstream(self) -> bool:
        return self._has_upstream

    def set_auth_header(self, auth_header: str) -> None:
        """Set the Authorization header for requests."""
        self._auth_headers["Authorization"] = auth_header

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        hello_frame = NodeHelloFrame(
            system_id=system_id,
            instance_id=instance_id,
            logicals=requested_logicals or [],
            supported_transports=self._supported_transports,
        )
        envelope = FameEnvelope(frame=hello_frame)
        payload = envelope.model_dump_json(by_alias=True, exclude_none=True)

        # Create session for this request only if not provided
        session = self._session
        session_owned = False
        if session is None:
            session = aiohttp.ClientSession()
            session_owned = True

        try:
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            headers.update(self._auth_headers)

            # Send HTTP request
            async with session.post(
                self._url,
                data=payload,
                headers=headers,
            ) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise RuntimeError(
                        f"[WelcomeServiceClient] failed to connect to {self._url}. "
                        f"HTTP {resp.status}: {text}"
                    )
                data = json.loads(text)

            # Decode into a FameEnvelope
            envelope = FameEnvelope.model_validate(data, by_alias=True)

            # Validate frame type
            if not isinstance(envelope.frame, NodeWelcomeFrame):
                raise RuntimeError(f"[WelcomeServiceClient] Unexpected frame type '{envelope.frame.type}'")
            return envelope  # type: ignore
        finally:
            # Close session if we created it for this request
            if session_owned:
                await session.close()

    async def close(self) -> None:
        """
        Close the underlying aiohttp session and auth strategy.
        """
        if self._auth_strategy:
            await self._auth_strategy.cleanup()

        if self._session:
            await self._session.close()
            self._session = None
