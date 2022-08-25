"""
Custom datasource for gathering a list of encrypted LUKS block devices.
"""
from insights.core.context import HostContext
from insights.core.dr import SkipComponent
from insights.core.plugins import datasource
from insights.parsers.blkid import BlockIDInfo


@datasource(BlockIDInfo, HostContext)
def LUKS_block_devices(broker):
    """
    This datasource provides a list of LUKS encrypted device.

    Sample data returned::

        ['/dev/sda', '/dev/nvme0n1p3']

    Returns:
        list: List of the LUKS encrypted block devices.

    Raises:
        SkipComponent: When there is not any LUKS encrypted block device.
    """

    block_id = broker[BlockIDInfo]
    if block_id:
        devices = block_id.filter_by_type("crypto_LUKS")
        if devices:
            return sorted(map(lambda x: x["NAME"], devices))

    raise SkipComponent
