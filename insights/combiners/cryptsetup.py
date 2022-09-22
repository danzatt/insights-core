"""
Cryptsetup - combine metadata about LUKS devices
================================================

Use LuksDump parser to filter just LUKS version 1 devices and return their
paths (by UUID).
"""

from insights import SkipComponent
from insights.core.plugins import combiner
from insights.parsers.cryptsetup_luksDump import LuksDump


@combiner(LuksDump)
def luks1_block_devices(dumps):
    """
    This combiner provides a list of LUKS version 1 encrypted device.

    Sample data returned::

        ['/dev/disk/by-uuid/2a6c383b-f57c-4a77-8da2-a83b2e4aa9c5', '/dev/disk/by-uuid/76f799fd-8aaa-4b25-828c-976db6a54307']

    Returns:
        list: List of the LUKS version 1 encrypted block devices.

    Raises:
        SkipComponent: When there is not any LUKS version 1 encrypted block
        device on the system.
    """

    luks1_devices = []
    for luks_device in filter(lambda x: x.dump["header"]["Version"] == "1", dumps):
        luks1_devices.append("/dev/disk/by-uuid/" + luks_device.dump["header"]["UUID"])

    if not luks1_devices:
        raise SkipComponent
    return luks1_devices
