"""Content-safe domain errors.

Exception messages in this module are suitable for routine CLI/API output. Raw
evidence, request bodies, credentials, and upstream response bodies must never
be interpolated into them.
"""


class VerityError(Exception):
    """Base class for expected, content-safe Verity failures."""

    code = "verity_error"


class ConfigurationError(VerityError):
    code = "configuration_error"


class KeyHealthError(VerityError):
    code = "key_health_error"


class LedgerError(VerityError):
    code = "ledger_error"


class LedgerIntegrityError(LedgerError):
    code = "ledger_integrity_error"


class LedgerUnavailableError(LedgerError):
    code = "ledger_unavailable"


class PolicyError(VerityError):
    code = "policy_error"


class PolicyValidationError(PolicyError):
    code = "policy_validation_error"


class SemanticProviderError(VerityError):
    code = "semantic_provider_error"


class AuthorizationError(VerityError):
    code = "authorization_error"


class RateLimitError(AuthorizationError):
    code = "rate_limited"


class ConflictError(VerityError):
    code = "state_conflict"


class NotFoundError(VerityError):
    code = "not_found"


class ResourceLimitError(VerityError):
    code = "resource_limit"
