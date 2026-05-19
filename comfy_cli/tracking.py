import functools
import json
import logging as logginglib
import sys
import uuid

import typer
from mixpanel import Mixpanel

from comfy_cli import constants, logging, ui
from comfy_cli.config_manager import ConfigManager
from comfy_cli.workspace_manager import WorkspaceManager

# Ignore logs from urllib3 that Mixpanel uses.
logginglib.getLogger("urllib3").setLevel(logginglib.ERROR)

MIXPANEL_TOKEN = "93aeab8962b622d431ac19800ccc9f67"
mp = Mixpanel(MIXPANEL_TOKEN) if MIXPANEL_TOKEN else None

# ---------------------------------------------------------------------------
# Sensitive-kwarg redaction and kwarg filtering for track_command()
#
# Historical context (BE-992): the original SENSITIVE_TRACKING_KEYS only
# matched "api_key" by exact name, missing kwargs such as
# set_civitai_api_token and set_hf_api_token.  Separately, the kwarg filter
# dropped "ctx" and "context" but not "_ctx" (underscore-prefixed Click
# Context).  These two gaps *cancelled each other out*: the un-redacted
# credential payload always included the non-JSON-serializable _ctx object,
# so mp.track() raised a TypeError before the event reached Mixpanel.
#
# Fixing the underscore-prefix filter without also broadening the credential
# allowlist would silently activate a CWE-200 credential leak.  Both filters
# are therefore fixed atomically here.
# ---------------------------------------------------------------------------

_SENSITIVE_SUFFIXES = ("_token", "_api_key", "_secret", "_password")
_SENSITIVE_EXACT = frozenset({"api_key", "token", "password", "secret"})


def _is_sensitive(name: str) -> bool:
    """Return True if *name* looks like it holds a credential or secret."""
    return name in _SENSITIVE_EXACT or name.endswith(_SENSITIVE_SUFFIXES)


def _is_trackable(name: str, value: object) -> bool:
    """Return True if the kwarg (name, value) pair is safe to include in a tracking event.

    Excluded:
    * ``ctx`` / ``context`` — Click context objects passed by Typer.
    * Any name starting with ``_`` — covers ``_ctx`` and other private/internal params.
    * Values that are not JSON-serializable — defensive guard so a single
      unserializable kwarg doesn't silently swallow the entire event.
    """
    if name in ("ctx", "context"):
        return False
    if name.startswith("_"):
        return False
    try:
        json.dumps(value)
    except (TypeError, ValueError, OverflowError):
        return False
    return True

# Generate a unique tracing ID per command.
config_manager = ConfigManager()
cli_version = config_manager.get_cli_version()

# tracking all events for a single user
user_id = config_manager.get(constants.CONFIG_KEY_USER_ID)
# tracking all events for a single command
tracing_id = str(uuid.uuid4())
workspace_manager = WorkspaceManager()

# Process-scoped opt-in used when running non-interactively before the
# user has ever recorded a consent choice. Captures agentic usage without
# persisting the consent flag, so a later interactive run can still
# prompt the human. The anonymous user_id is persisted separately for
# stable agent identity in analytics.
_session_only_tracking = False

app = typer.Typer()


@app.command()
def enable():
    init_tracking(True)
    typer.echo(f"Tracking is now {'enabled'}.")
    init_tracking(True)


@app.command()
def disable():
    init_tracking(False)
    typer.echo(f"Tracking is now {'disabled'}.")


def track_event(event_name: str, properties: any = None):
    if properties is None:
        properties = {}
    logging.debug(f"tracking event called with event_name: {event_name} and properties: {properties}")
    enable_tracking = config_manager.get_bool(constants.CONFIG_KEY_ENABLE_TRACKING)
    if not enable_tracking and not _session_only_tracking:
        return

    try:
        properties["cli_version"] = cli_version
        properties["tracing_id"] = tracing_id
        mp.track(distinct_id=user_id, event_name=event_name, properties=properties)
    except Exception as e:
        logging.warning(f"Failed to track event: {e}")  # Log the error but do not raise


def track_command(sub_command: str = None):
    """
    A decorator factory that logs the command function name and selected arguments when it's called.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            command_name = f"{sub_command}:{func.__name__}" if sub_command is not None else func.__name__

            filtered_kwargs = {
                k: ("<redacted>" if v is not None else None) if _is_sensitive(k) else v
                for k, v in kwargs.items()
                if _is_trackable(k, v)
            }

            logging.debug(f"Tracking command: {command_name} with arguments: {filtered_kwargs}")
            track_event(command_name, properties=filtered_kwargs)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def prompt_tracking_consent(skip_prompt: bool = False, default_value: bool = False):
    global _session_only_tracking, user_id

    if _session_only_tracking:
        return

    tracking_enabled = config_manager.get_bool(constants.CONFIG_KEY_ENABLE_TRACKING)
    if tracking_enabled is not None:
        return

    if skip_prompt:
        init_tracking(default_value)
        return

    # When stdin or stdout is not a TTY (subprocess pipe, redirect, CI),
    # blocking on the consent prompt would either hang the caller forever
    # or corrupt their output stream. Enable tracking for this process and
    # persist a stable anonymous user_id so repeat agentic usage from the
    # same machine attributes to one identity. The consent flag itself
    # stays unset so a later interactive run can still ask the human; if
    # they consent, init_tracking will reuse this user_id.
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        _session_only_tracking = True
        if user_id is None:
            user_id = str(uuid.uuid4())
            # Best-effort persistence — a read-only config dir (fresh CI,
            # restricted sandbox) must not crash the caller. If the write
            # fails we keep the in-memory user_id so this process still
            # tracks normally; the next run on a writable host will retry.
            try:
                config_manager.set(constants.CONFIG_KEY_USER_ID, user_id)
            except OSError:
                pass
        return

    enable_tracking = ui.prompt_confirm_action("Do you agree to enable tracking to improve the application?", False)
    init_tracking(enable_tracking)


def init_tracking(enable_tracking: bool):
    """
    Initialize the tracking system by setting the user identifier and tracking enabled status.
    """
    global user_id
    logging.debug(f"Initializing tracking with enable_tracking: {enable_tracking}")
    config_manager.set(constants.CONFIG_KEY_ENABLE_TRACKING, str(enable_tracking))
    if not enable_tracking:
        return

    curr_user_id = config_manager.get(constants.CONFIG_KEY_USER_ID)
    logging.debug(f'User identifier for tracking user_id found: {curr_user_id}."')
    if curr_user_id is None:
        curr_user_id = str(uuid.uuid4())
        config_manager.set(constants.CONFIG_KEY_USER_ID, curr_user_id)
        logging.debug(f'Setting user identifier for tracking user_id: {curr_user_id}."')
    user_id = curr_user_id

    # Note: only called once when the user interacts with the CLI for the
    #  first time iff the permission is granted.
    install_event_triggered = config_manager.get_bool(constants.CONFIG_KEY_INSTALL_EVENT_TRIGGERED)
    if not install_event_triggered:
        logging.debug("Tracking install event.")
        config_manager.set(constants.CONFIG_KEY_INSTALL_EVENT_TRIGGERED, "True")
        track_event("install")
