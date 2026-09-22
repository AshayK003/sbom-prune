"""Fixture app: vulnlib used, unusedlib imported-never-used, cleanlib used."""

import cleanlib
import unusedlib
import vulnlib


def run():
    data = vulnlib.parse("hello")
    return cleanlib.render(data)
