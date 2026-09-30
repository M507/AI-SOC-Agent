"""Errors the detection routes turn into HTTP responses.

status_code is the HTTP status. 400 is an analyst-input problem, 404 a
missing rule or alert, 409 a missing folder or a file that changed under
the review, 502 a model or Elastic failure. See
documentation/detection-as-code.md.
"""


class DetectionError(Exception):
    """A detection action that should not continue."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code
