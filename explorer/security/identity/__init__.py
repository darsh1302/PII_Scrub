"""Authentication, sessions and authorization — task 3.

Placed under ``explorer.security`` rather than in ``explorer.api``, which the design
sketch implied. Two reasons.

The Streamlit experience layer and the FastAPI application both need to authenticate,
and identity logic living inside one of them would be reached from the other by an
import that crosses a layer. And a password verifier that can only be tested through
an HTTP client is a password verifier that will be tested less thoroughly than it
should be — the KDF parameters, the timing behaviour and the session expiry are all
things to assert directly.

The API stays a thin caller. Nothing here imports a web framework, and
``tests/architecture`` lists this package among the deterministic services, so
nothing here can reach a model either.

Subject to the same rule as the rest of the platform: ``workspace_id`` is an explicit
parameter. An authenticated identity is not a workspace scope, and conflating them is
how a request ends up reading whatever the last session touched.
"""
