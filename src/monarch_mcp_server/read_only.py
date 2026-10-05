"""Opt in read only mode.

Set ``MONARCH_MCP_READ_ONLY`` to a truthy value and the mutating tools are
never registered, so they do not appear in the tool list and cannot be called
at all. This is stronger than relying on client side approval prompts: a tool
that is not registered cannot be invoked by a model that was talked into it by
a merchant name or memo it read back, which is the threat the README's
approval section is about.

Read only is off by default. Enabling it is a deliberate choice, so existing
setups keep working exactly as before.

Curated write allowlist
------------------------

``MONARCH_MCP_READ_ONLY`` is all or nothing: on, every mutating tool is hidden;
off, every mutating tool is exposed. Some deployments want a narrow middle
ground, for example a transaction categoriser that may create rules and
recategorise transactions but must never delete anything or touch the stored
session.

``MONARCH_MCP_WRITE_ALLOW`` provides exactly that, and ONLY while read only is
on. It is a comma separated list of mutating tool names that are re-exposed on
top of the read tools. The direction is deliberate and fail closed:

* It is a strict subset of ``MUTATING_TOOLS``. A name that is not a known
  mutating tool is ignored (and logged), so a typo widens nothing.
* It can never re-expose a tool in ``NEVER_ALLOWLISTABLE`` -- the session
  mutators and the destructive deletes/account writes. Listing one is ignored
  and logged. This is why an over broad or copy pasted allowlist cannot turn
  into "log me out" or "delete that transaction".
* It does nothing at all unless ``MONARCH_MCP_READ_ONLY`` is truthy. With read
  only off there is no gate to open, so the allowlist is a no-op by
  construction rather than by a second check.

So the exposed set is: read tools, plus (allowlist ∩ MUTATING_TOOLS) minus
NEVER_ALLOWLISTABLE. Everything else stays unregistered.
"""

import logging
import os
from typing import Any, Callable, FrozenSet, TypeVar

logger = logging.getLogger(__name__)

ENV_VAR = "MONARCH_MCP_READ_ONLY"
WRITE_ALLOW_ENV_VAR = "MONARCH_MCP_WRITE_ALLOW"

_TRUTHY = frozenset({"1", "true", "t", "yes", "y", "on"})

# Every registered tool that writes. Listed explicitly rather than matched by
# name prefix: this is a security control, and a tool silently failing to be
# recognised as mutating would defeat the whole point.
MUTATING_TOOLS: FrozenSet[str] = frozenset(
    {
        # Transactions
        "create_transaction",
        "update_transaction",
        "delete_transaction",
        "categorize_transaction",
        "update_transaction_notes",
        "mark_transaction_reviewed",
        "bulk_categorize_transactions",
        "bulk_update_transactions",
        "split_transaction",
        "upload_account_balance_history",
        # Tags
        "set_transaction_tags",
        "add_transaction_tag",
        "create_transaction_tag",
        # Rules
        "create_transaction_rule",
        "update_transaction_rule",
        "delete_transaction_rule",
        "reorder_transaction_rule",
        # Categories and budgets
        "create_transaction_category",
        "update_category",
        "set_budget_amount",
        # Goals
        "update_savings_goal",
        "set_goal_contribution",
        # Merchants
        "update_merchant",
        "review_recurring_stream",
        # Session mutation. Logging out or replacing the stored session is a
        # change to durable state, and a read only deployment should not be
        # able to do it either.
        "monarch_login",
        "monarch_login_with_token",
        "monarch_logout",
        # Accounts
        "update_account",
        # Side effecting: posts a refresh request to the institutions.
        "refresh_accounts",
    }
)

# Tools that MONARCH_MCP_WRITE_ALLOW must never be able to re-expose, even if
# named explicitly. These change durable session state or destroy data, and no
# categorisation-style workload needs them. Keeping this as a hard floor means
# an over broad or copy pasted allowlist degrades to "ignored and logged"
# rather than silently handing an unauthenticated caller "log me out" or
# "delete that transaction". It is a strict subset of MUTATING_TOOLS (asserted
# in tests), so it never gates a read tool by accident.
NEVER_ALLOWLISTABLE: FrozenSet[str] = frozenset(
    {
        # Session mutation -- replacing or dropping the stored credential.
        "monarch_login",
        "monarch_login_with_token",
        "monarch_logout",
        # Destructive -- irreversible data loss.
        "delete_transaction",
        "delete_transaction_rule",
        # Account writes and institution side effects.
        "update_account",
        "refresh_accounts",
    }
)

F = TypeVar("F", bound=Callable[..., Any])


def _write_allowlist() -> FrozenSet[str]:
    """The curated write tools to re-expose while read only is on.

    Parsed from ``MONARCH_MCP_WRITE_ALLOW`` (comma separated). Fail closed:
    names that are not known mutating tools, or that are in
    ``NEVER_ALLOWLISTABLE``, are dropped and logged rather than honoured, so a
    typo or an over broad list can only ever expose LESS than intended, never
    more. Returns the effective set actually permitted.
    """
    raw = os.environ.get(WRITE_ALLOW_ENV_VAR, "")
    requested = {name.strip() for name in raw.split(",") if name.strip()}
    if not requested:
        return frozenset()

    permitted = set()
    for name in requested:
        if name in NEVER_ALLOWLISTABLE:
            logger.warning(
                "%s: refusing to allowlist %r -- it is never allowlistable "
                "(session/destructive/account tool); ignoring",
                WRITE_ALLOW_ENV_VAR,
                name,
            )
            continue
        if name not in MUTATING_TOOLS:
            logger.warning(
                "%s: ignoring %r -- not a known mutating tool", WRITE_ALLOW_ENV_VAR, name
            )
            continue
        permitted.add(name)
    return frozenset(permitted)


def is_read_only() -> bool:
    """Whether read only mode is enabled for this process."""
    return os.environ.get(ENV_VAR, "").strip().lower() in _TRUTHY


def install(mcp: Any) -> None:
    """Make ``mcp.tool()`` skip mutating tools while read only is enabled.

    Wrapping registration is what keeps this change small: every tool module
    already registers through ``@mcp.tool()``, so nothing else has to know
    about read only mode, and the decorated function is still returned so the
    re-exports in ``server.py`` keep working.
    """
    if not is_read_only():
        return

    allowlist = _write_allowlist()
    # The tools actually hidden: every mutating tool except the ones the
    # operator explicitly (and permissibly) allowlisted.
    gated = MUTATING_TOOLS - allowlist

    original_tool = mcp.tool

    def guarded_tool(*args: Any, **kwargs: Any) -> Callable[[F], F]:
        register = original_tool(*args, **kwargs)

        def decorator(fn: F) -> F:
            # FastMCP.tool() takes `name` as its first positional parameter, so
            # @mcp.tool("some_name") must be honoured too. Comparing only
            # fn.__name__ would let a renamed mutating tool through the gate.
            positional = args[0] if args and isinstance(args[0], str) else None
            name = positional or kwargs.get("name") or getattr(fn, "__name__", "")
            if name in gated:
                logger.info("Read only mode: not registering %s", name)
                return fn
            return register(fn)

        return decorator

    mcp.tool = guarded_tool  # type: ignore[method-assign]
    if allowlist:
        logger.warning(
            "%s is set: %d mutating tools hidden; %s re-exposes %d: %s",
            ENV_VAR,
            len(gated),
            WRITE_ALLOW_ENV_VAR,
            len(allowlist),
            ", ".join(sorted(allowlist)),
        )
    else:
        logger.warning(
            "%s is set: %d mutating tools will not be registered",
            ENV_VAR,
            len(gated),
        )
