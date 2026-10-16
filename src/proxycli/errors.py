"""Application errors. Messages are safe to print; they must not include secrets."""


class ProxyCLIError(Exception):
    def __init__(self, message: str, *, fix: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.fix = fix

    def __str__(self) -> str:
        return self.message


class ValidationError(ProxyCLIError):
    pass


class ProbeError(ProxyCLIError):
    def __init__(self, message: str, *, layer: str, fix: str = "") -> None:
        super().__init__(message, fix=fix)
        self.layer = layer


class RollbackError(ProxyCLIError):
    pass
