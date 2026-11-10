"""Parse JSON numeric tokens without silently changing policy inputs."""

import math
from decimal import Decimal, InvalidOperation


MAX_JSON_NUMBER_LENGTH = 512


def bounded_int(text):
    if len(text) > MAX_JSON_NUMBER_LENGTH:
        raise ValueError("Die JSON-Zahl überschreitet das unterstützte Längenlimit.")
    return int(text)


def finite_float(text):
    if len(text) > MAX_JSON_NUMBER_LENGTH:
        raise ValueError("Die JSON-Zahl überschreitet das unterstützte Längenlimit.")
    number = float(text)
    if not math.isfinite(number):
        raise ValueError("Die JSON-Zahl liegt außerhalb des unterstützten Bereichs.")

    try:
        exact = Decimal(text)
        if exact == exact.to_integral_value():
            # Preserve integral values that a binary float would round.
            return int(exact)
        if exact == Decimal(str(number)):
            return number
    except InvalidOperation as exc:
        raise ValueError("Die JSON-Zahl liegt außerhalb des unterstützten Bereichs.") from exc
    raise ValueError("Die JSON-Zahl lässt sich nicht ohne Rundung verarbeiten.")
