"""Exception types. Content problems are reported as findings; exceptions are for usage errors."""


class RosettalogError(Exception):
    """Base class for errors shown to the user without a traceback."""


class PluginError(RosettalogError):
    pass


class InputError(RosettalogError):
    pass
