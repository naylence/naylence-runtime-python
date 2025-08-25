"""
TTL (Time-To-Live) constants for consistent timeout configuration across the Fame runtime.

This module provides standardized TTL values to ensure consistency across different
components and eliminate hardcoded timeout values scattered throughout the codebase.
"""

# Node attachment TTL defaults
DEFAULT_NODE_ATTACH_TTL_SEC = 3600  # 1 hour - reasonable for node attachments
MAX_NODE_ATTACH_TTL_SEC = 86400  # 24 hours - maximum allowed attachment time

# Key correlation and caching TTL defaults
DEFAULT_KEY_CORRELATION_TTL_SEC = 30  # 30 seconds - for key request routing
DEFAULT_JWKS_CACHE_TTL_SEC = 300  # 5 minutes - for JWKS caching

# Authentication and authorization TTL defaults
DEFAULT_JWT_TOKEN_TTL_SEC = 3600  # 1 hour - standard JWT token lifetime
DEFAULT_OAUTH2_TTL_SEC = 3600  # 1 hour - OAuth2 authorization lifetime
MAX_OAUTH2_TTL_SEC = 86400  # 24 hours - maximum OAuth2 authorization
DEFAULT_REVERSE_AUTH_TTL_SEC = 86400  # 24 hours - reverse authentication

# Admission and transport TTL defaults
DEFAULT_ADMISSION_TTL_SEC = 3600  # 1 hour - node admission lifetime
DEFAULT_DIRECT_ADMISSION_TTL_SEC = 86400  # 24 hours - direct admission fallback (no welcome service)
DEFAULT_TRANSPORT_TTL_SEC = 3600  # 1 hour - transport provisioning lifetime
DEFAULT_WELCOME_TTL_SEC = 3600  # 1 hour - welcome service lifetime

# Crypto provider TTL defaults
DEFAULT_CRYPTO_PROVIDER_TTL_SEC = 3600  # 1 hour - crypto provider cache lifetime

# Special TTL values
TTL_NEVER_EXPIRES = 0  # 0 indicates no expiration
TTL_IMMEDIATE_EXPIRY = -1  # -1 indicates immediate expiration

# Test TTL values (shorter for faster test execution)
TEST_SHORT_TTL_SEC = 2  # 2 seconds - for TTL expiry tests
TEST_MEDIUM_TTL_SEC = 10  # 10 seconds - for medium-duration tests
TEST_LONG_TTL_SEC = 600  # 10 minutes - for longer test scenarios
