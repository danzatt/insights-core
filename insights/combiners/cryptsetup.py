"""
Cryptsetup - combine metadata about LUKS devices
================================================

Use LuksDump parser to filter just LUKS version 1 devices and return their
paths (by UUID). Also combine outputs of LuksDump and LuksMeta parsers (with
the same UUID) into a single LuksDevice.
"""

import copy

from insights import SkipComponent
from insights.core.plugins import combiner
from insights.parsers.cryptsetup_luksDump import LuksDump
from insights.parsers.luksmeta import LuksMeta


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


@combiner(LuksDump, optional=[LuksMeta])
class LuksDevices(list):
    """
    Combiner for LUKS encrypted devices information. It uses the results of
    the ``LuksDump`` and ``LuksMeta`` parser (they are matched based UUID of
    the device they were collected from).


    Examples:
        >>> luks_devices[0]["header"]["Version"]
        '1'
        >>> "luksmeta" in luks_devices[0]
        True
        >>> "luksmeta" in luks_devices[1]
        False
        >>> luks_devices[0]["luksmeta"][0]
        Keyslot on index 0 is 'active' with no embedded metadata
    """

    def __init__(self, luks_dumps, luks_metas):
        luksmeta_by_uuid = {}

        if luks_metas:
            for luks_meta in luks_metas:
                if "device_uuid" not in luks_meta:
                    continue

                luksmeta_by_uuid[luks_meta["device_uuid"].lower()] = luks_meta

        for luks_dump in luks_dumps:
            uuid = luks_dump.dump["header"]["UUID"].lower()
            luks_dump_copy = copy.deepcopy(luks_dump.dump)

            if luks_metas and uuid in luksmeta_by_uuid:
                luks_dump_copy["luksmeta"] = luksmeta_by_uuid[uuid]

            self.append(luks_dump_copy)
