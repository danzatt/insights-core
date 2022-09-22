"""
Custom datasource for gathering a list of encrypted LUKS block devices and their properties.
"""
from insights.components.cryptsetup import HasCryptsetupWithTokens, HasCryptsetupWithoutTokens
from insights.core.context import HostContext
from insights.core.dr import SkipComponent
from insights.core.plugins import datasource
from insights.core.spec_factory import DatasourceProvider, foreach_execute
from insights.parsers.blkid import BlockIDInfo
from insights.parsers.cryptsetup_luksDump import LuksDump
from insights.specs import Specs
import re


@datasource(BlockIDInfo, HostContext)
def luks_block_devices(broker):
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


class LocalSpecs(Specs):
    """ Local specs used only by LUKS_data_sources datasource. """
    cryptsetup_luks_dump_token_commands = foreach_execute(luks_block_devices, "cryptsetup luksDump --disable-external-tokens %s", deps=[luks_block_devices, HasCryptsetupWithTokens])
    cryptsetup_luks_dump_commands = foreach_execute(luks_block_devices, "cryptsetup luksDump %s", deps=[luks_block_devices, HasCryptsetupWithoutTokens])


def line_indentation(line):
    """
    Compute line indentation level

    Arguments:
        line(str): The whole line

    Returns:
        int: the number of spaces the line is indentated by
    """
    line = line.replace("\t", " " * 8)
    return len(line) - len(line.lstrip())


def filter_token_lines(lines):
    """
    Filter out token descriptions to keep just the Keyslot filed

    Arguments:
        lines(list): List of lines of the luksDump output

    Returns:
        list: The original lines, except the tokens section only contains only token name and associated keyslot
    """
    in_tokens = False
    remove_indices = []

    for i, line in enumerate(lines):
        if line == "Tokens:":
            in_tokens = True
            continue

        if in_tokens and line_indentation(line) == 0:
            in_tokens = False

        if not in_tokens or line_indentation(line) == 2 or line.startswith("\tKeyslot:"):
            continue

        remove_indices.append(i)

    return [i for j, i in enumerate(lines) if j not in remove_indices]


@datasource(HostContext, [LocalSpecs.cryptsetup_luks_dump_token_commands, LocalSpecs.cryptsetup_luks_dump_commands])
def luks_data_sources(broker):
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

    commands = []
    if LocalSpecs.cryptsetup_luks_dump_token_commands in broker:
        commands.extend(broker[LocalSpecs.cryptsetup_luks_dump_token_commands])
    if LocalSpecs.cryptsetup_luks_dump_commands in broker:
        commands.extend(broker[LocalSpecs.cryptsetup_luks_dump_commands])

    for command in commands:
        lines_without_tokens = filter_token_lines(command.content)

        regex = re.compile(r'[\t ]*(MK digest:|MK salt:|Salt:|Digest:)(\s*([a-z0-9][a-z0-9] ){16}\n)*(\s*([a-z0-9][a-z0-9] )+\n)?', flags=re.IGNORECASE)
        filtered_content = regex.sub("", "\n".join(lines_without_tokens) + "\n")

        datasources.append(
            DatasourceProvider(content=filtered_content, relative_path="insights_commands/" + command.cmd.replace("/", ".").replace(" ", "_"))
        )

    if datasources:
        return datasources

    raise SkipComponent


@datasource(LuksDump, HostContext)
def luks1_block_devices(broker):
    """
    This datasource provides a list of LUKS version 1 encrypted device.

    Sample data returned::

        ['/dev/disk/by-uuid/2a6c383b-f57c-4a77-8da2-a83b2e4aa9c5', '/dev/disk/by-uuid/76f799fd-8aaa-4b25-828c-976db6a54307']

    Returns:
        list: List of the LUKS version 1 encrypted block devices.

    Raises:
        SkipComponent: When there is not any LUKS version 1 encrypted block
        device on the system.
    """
    luks1_devices = []
    for luks_device in filter(lambda x: x.dump["header"]["Version"] == "1", broker[LuksDump]):
        luks1_devices.append("/dev/disk/by-uuid/" + luks_device.dump["header"]["UUID"])

    if not luks1_devices:
        raise SkipComponent
    return luks1_devices
