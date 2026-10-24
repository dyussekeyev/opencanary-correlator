"""SMTP dispatcher using `aiosmtplib`.

Email is sent through any relay the operator already trusts (Mailchimp
Transactional SMTP, SES, Exchange, Postfix); there is no vendor SDK.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from email.message import EmailMessage
from typing import Any, ClassVar

import aiosmtplib
from pydantic import SecretStr

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.dispatchers.base import RetryPolicy

SendFunction = Callable[..., Awaitable[Any]]


class SmtpDispatcher(BaseDispatcher):
    """Send incidents by email."""

    name: ClassVar[str] = "smtp"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        username: str | None = None,
        password: SecretStr | None = None,
        start_tls: bool = True,
        timeout: float = 10.0,
        retry: RetryPolicy | None = None,
        send: SendFunction = aiosmtplib.send,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = list(recipients)
        self._username = username
        self._password = password
        self._start_tls = start_tls
        self._timeout = timeout
        self._retry = retry or RetryPolicy()
        self._send = send
        self._sleep = sleep

    def build_message(self, incident: IncidentLike) -> EmailMessage:
        """Render the plain-text alert email."""
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message["Subject"] = incident.format_title()
        message.set_content(incident.format_report())
        return message

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        """Deliver the email with retries, never raising."""
        if not self._recipients:
            return DispatchResult(dispatcher=self.name, status="skipped", detail="no_recipients")

        message = self.build_message(incident)
        password = self._password.get_secret_value() if self._password else None
        detail = "no_attempt"
        for attempt in range(1, self._retry.attempts + 1):
            try:
                await self._send(
                    message,
                    sender=self._sender,
                    recipients=self._recipients,
                    hostname=self._host,
                    port=self._port,
                    username=self._username,
                    password=password,
                    start_tls=self._start_tls,
                    timeout=self._timeout,
                )
            except (aiosmtplib.SMTPException, OSError, TimeoutError) as exc:
                detail = type(exc).__name__
                if attempt < self._retry.attempts:
                    await self._sleep(
                        min(
                            self._retry.base_delay * (2 ** (attempt - 1)),
                            self._retry.max_delay,
                        )
                    )
            else:
                return DispatchResult(dispatcher=self.name, status="success")
        return DispatchResult(dispatcher=self.name, status="error", detail=detail)


__all__ = ["SmtpDispatcher"]
