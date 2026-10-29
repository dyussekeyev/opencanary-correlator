"""SMTP dispatcher using `aiosmtplib`.

Email is sent through any relay the operator already trusts (Mailchimp
Transactional SMTP, SES, Exchange, Postfix); there is no vendor SDK.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from email.message import EmailMessage
from typing import TYPE_CHECKING, Any, ClassVar

import aiosmtplib
from pydantic import SecretStr

from opencanary_correlator.connectors.base import BaseDispatcher, DispatchResult, IncidentLike
from opencanary_correlator.connectors.dispatchers.alert_text import (
    AlertDetail,
    render_alert,
    render_service_message,
)
from opencanary_correlator.connectors.dispatchers.base import RetryPolicy
from opencanary_correlator.redaction import sanitize_text

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opencanary_correlator.core.service_messages import ServiceMessage

SendFunction = Callable[..., Awaitable[Any]]


class SmtpDispatcher(BaseDispatcher):
    """Send incidents by email.

    ``detail`` selects the body layout: ``minimal`` keeps the legacy plain-text
    report, ``standard`` and ``detailed`` send the multiline layout without
    markup (mail clients do not render chat markdown). The default matches the
    configuration default: a person reads the mail, so it gets the readable
    layout with the attacker context.
    """

    name: ClassVar[str] = "smtp"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        detail: AlertDetail = "standard",
        username: str | None = None,
        password: SecretStr | None = None,
        start_tls: bool = True,
        use_tls: bool = False,
        timeout: float = 10.0,
        retry: RetryPolicy | None = None,
        send: SendFunction = aiosmtplib.send,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = list(recipients)
        self._detail: AlertDetail = detail
        self._username = username
        self._password = password
        self._start_tls = start_tls
        self._use_tls = use_tls
        self._timeout = timeout
        self._retry = retry or RetryPolicy()
        self._send = send
        self._sleep = sleep

    def build_message(self, incident: IncidentLike) -> EmailMessage:
        """Render the plain-text alert email.

        Header values go through :func:`sanitize_text`. `EmailMessage` already
        rejects a header containing CR/LF, which blocks the injection, but the
        rejection is an exception raised mid-render: the alert would be lost and
        the payload (`node_id` is a honeypot field) could not be delivered at
        all. Flattening the header keeps both properties.
        """
        message = EmailMessage()
        message["From"] = sanitize_text(self._sender)
        message["To"] = sanitize_text(", ".join(self._recipients))
        message["Subject"] = sanitize_text(incident.format_title())
        body = (
            incident.format_report()
            if self._detail == "minimal"
            else render_alert(incident, detail=self._detail, flavor="plain")
        )
        message.set_content(body)
        return message

    def build_service_message(self, message: ServiceMessage) -> EmailMessage:
        """Render a service message as mail: severity and title in the subject.

        The subject is flattened for the same reason an alert subject is: a
        header split by a line break is an injection, and the title is built from
        a fixed template but still goes through the same guard.
        """
        mail = EmailMessage()
        mail["From"] = sanitize_text(self._sender)
        mail["To"] = sanitize_text(", ".join(self._recipients))
        subject = f"[{message.severity.value}] {message.title}"
        mail["Subject"] = sanitize_text(subject)
        mail.set_content(render_service_message(message, flavor="plain"))
        return mail

    async def notify(self, message: ServiceMessage) -> DispatchResult:
        """Deliver a service message with the same recipients and retries."""
        if not self._recipients:
            return DispatchResult(dispatcher=self.name, status="skipped", detail="no_recipients")
        try:
            mail = self.build_service_message(message)
        except (TypeError, ValueError) as exc:
            return DispatchResult(dispatcher=self.name, status="error", detail=type(exc).__name__)
        return await self._send_with_retries(mail)

    def build_notice_message(self, body: str) -> EmailMessage:
        """Render an operator notice: the first line is the subject, the rest the body.

        A summary has no incident title, but a mail without a subject is filtered
        away by most clients, so the headline the renderer already wrote becomes
        one. It is flattened for the same reason as the alert subject.
        """
        message = EmailMessage()
        message["From"] = sanitize_text(self._sender)
        message["To"] = sanitize_text(", ".join(self._recipients))
        headline = next((line for line in body.splitlines() if line.strip()), "")
        message["Subject"] = sanitize_text(headline) or "OpenCanary notice"
        message.set_content(body)
        return message

    async def announce(self, message: str) -> DispatchResult:
        """Deliver a notice with the same recipients and retries as an alert."""
        if not self._recipients:
            return DispatchResult(dispatcher=self.name, status="skipped", detail="no_recipients")
        try:
            notice = self.build_notice_message(message)
        except (TypeError, ValueError) as exc:
            return DispatchResult(dispatcher=self.name, status="error", detail=type(exc).__name__)
        return await self._send_with_retries(notice)

    async def dispatch(self, incident: IncidentLike) -> DispatchResult:
        """Deliver the email with retries, never raising."""
        if not self._recipients:
            return DispatchResult(dispatcher=self.name, status="skipped", detail="no_recipients")

        try:
            message = self.build_message(incident)
        except (TypeError, ValueError) as exc:
            # Rendering must not escape `dispatch`: the contract is to return the
            # outcome, so a malformed incident is audited instead of surfacing as
            # an exception and losing the delivery silently.
            return DispatchResult(dispatcher=self.name, status="error", detail=type(exc).__name__)

        return await self._send_with_retries(message)

    async def _send_with_retries(self, message: EmailMessage) -> DispatchResult:
        """Send one rendered message, retrying a relay failure with backoff."""
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
                    use_tls=self._use_tls,
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
