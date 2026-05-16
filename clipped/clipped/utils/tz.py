from datetime import datetime, timedelta
import pytz
from typing import Optional

from dateutil.tz import tzlocal


try:
    from django.utils.timezone import now as dj_now  # pylint:disable=import-error
except ImportError:
    dj_now = None


def get_timezone(tz: Optional[str] = None):
    if tz:
        return pytz.timezone(tz)
    return tzlocal()


def now(tzinfo=True, no_micor=False):
    """
    Return an aware or naive datetime.datetime, depending on settings.USE_TZ.
    """
    value = None
    if dj_now:
        try:
            value = dj_now()
        except Exception:  # Improper configuration
            pass
    if not value:
        if tzinfo:
            value = datetime.utcnow().replace(tzinfo=pytz.utc)
        else:
            value = datetime.now()
    if no_micor:
        return value.replace(microsecond=0)
    return value


def local_datetime(datetime_value, tz=None):
    return datetime_value.astimezone(get_timezone(tz))


def get_datetime_from_now(
    days: float, hours: float = 0, minutes: float = 0, seconds: float = 0
) -> datetime:
    return now() - timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
