"""
Custom datasource for gathering a list of encrypted LUKS block devices and their properties.
"""
from insights.core.context import HostContext
from insights.core.dr import SkipComponent
from insights.core.plugins import datasource
from insights.core.spec_factory import DatasourceProvider, foreach_execute
from insights.parsers.blkid import BlockIDInfo
from insights.specs import Specs
import re


@datasource(BlockIDInfo, HostContext)
def Luks_block_devices(broker):
    """
    This datasource provides a list of LUKS encrypted device.

    Sample data returned::

        ['/dev/sda', '/dev/nvme0n1p3']

    Returns:
        list: List of the LUKS encrypted block devices.

    Raises:
        SkipComponent: When there is not any LUKS encrypted block device on the
        system.
    """

    block_id = broker[BlockIDInfo]
    if block_id:
        devices = block_id.filter_by_type("crypto_LUKS")
        if devices:
            return sorted(map(lambda x: x["NAME"], devices))

    raise SkipComponent


@datasource(Luks_block_devices)
class LocalSpecs(Specs):
    """ Local specs used only by LUKS_data_sources datasource. """
    cryptsetup_luksDump_commands = foreach_execute(Luks_block_devices, "cryptsetup luksDump --disable-external-tokens %s")


@datasource(HostContext, LocalSpecs.cryptsetup_luksDump_commands)
def Luks_data_sources(broker):
    """
    This datasource provides the output of 'cryptsetup luksDump' command for
    every LUKS encrypted device on the system. The digest and salt fields are
    filtered out as they can be potentially sensitive.

    Returns:
        list: List of outputs of the cryptsetup luksDump command.

    Raises:
        SkipComponent: When there is not any LUKS encrypted block device on the
        system.
    """
    datasources = []

    for command in broker[LocalSpecs.cryptsetup_luksDump_commands]:
        regex = re.compile(r'[\t ]*(MK digest:|MK salt:|Salt:|Digest:)(\s*([a-z0-9][a-z0-9] ){16}\n)*(\s*([a-z0-9][a-z0-9] )+\n)?', flags=re.IGNORECASE)
        filtered_content = regex.sub("", "\n".join(command.content) + "\n")

        datasources.append(
            DatasourceProvider(content=filtered_content, relative_path="insights_commands/" + command.cmd.replace("/", ".").replace(" ", "_"))
        )

    if datasources:
        return datasources

    raise SkipComponent
