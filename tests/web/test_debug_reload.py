import asyncio
import logging

from src.ai_controller.web.server import _ReloadCancelledErrorFilter


def _record(message, exception):
    record = logging.LogRecord(
        name="uvicorn.error",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=(type(exception), exception, None),
    )
    return record


def test_reload_filter_hides_only_cancelled_lifespan_tracebacks():
    error_filter = _ReloadCancelledErrorFilter()

    serialized = logging.LogRecord(
        name="uvicorn.error",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=(
            "Traceback:\n"
            '  File "/venv/site-packages/starlette/routing.py", line 655, in lifespan\n'
            "asyncio.exceptions.CancelledError"
        ),
        args=(),
        exc_info=None,
    )
    assert not error_filter.filter(serialized)
    assert not error_filter.filter(
        _record("Exception in 'lifespan' protocol", asyncio.CancelledError())
    )
    assert error_filter.filter(
        _record("Exception in 'lifespan' protocol", RuntimeError("real failure"))
    )
    assert error_filter.filter(
        _record("Unrelated task cancelled", asyncio.CancelledError())
    )
