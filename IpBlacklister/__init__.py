from pathlib import Path, PosixPath


# TODO add CLI support
# TODO clean up run / settings
# TODO rework logging to use the logger module
# TODO parse access.log for webdrivers etc + frequency of requests as well as check abuseipdb for better confidence
# TODO update readme
# TODO evaluate recent ips if they should be unbanned

PROJECT_ROOT: PosixPath = Path(__file__).parent.parent


class NoSuchMode(Exception):
    def __init__(self, modes):
        message = "Mode must be set to one of the following: " + ", ".join(modes) + ". Please edit `settings.json`"
        super(NoSuchMode, self).__init__(message)


__all__ = ["run_ip_blacklister"]
