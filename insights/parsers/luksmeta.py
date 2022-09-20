"""
luksmeta - command ``luksmeta show -d <device_name>``
=====================================================
This class provides parsing for the output of luksmeta <device_name>.
"""

from insights import parser, Parser, SkipComponent
from insights.specs import Specs


class KeyslotSpecification:
    """
    Class ``KeyslotSpecification`` describes information about a keyslot
    collected by the ``luksmeta show`` command.


    Attributes:
        index (int): the index of the described keyslot
        state (str): the state of the described keyslot
        metadata (str): the UUID of the application that stored metadata into
            the described keyslot
    """

    def __init__(self, index, state, metadata):
        self.index = index
        self.state = state
        self.metadata = metadata

    def __repr__(self):
        ret = "Keyslot on index " + str(self.index) + " is '" + self.state + "' "
        if self.metadata:
            ret += "with metadata stored by application with UUID '" + self.metadata + "'"
        else:
            ret += "with no embedded metadata"

        return ret


@parser(Specs.luksmeta)
class LuksMeta(Parser, dict):
    """
    Class ``LuksMeta`` parses the output of the ``luksmeta show -d <device>`` command.

    This command prints information if the device has custom user-defined
    metadata embedded in the keyslots (used e.g. by clevis). If the device was
    not initialized using ``luksmeta``, the parser raises SkipComponent.

    The parser can be indexed by the keyslot index (in the range 0-7).
    A KeyslotSpecification object is returned, which describes every LUKS
    keyslot. The KeyslotSpecification contains the ``index``, ``state`` and
    ``metadata`` fileds. Metadata field stores the UUID of the application that
    has stored metadata in the keyslot.

    Sample input data is in the format::

        0   active empty
        1   active cb6e8904-81ff-40da-a84a-07ab9ab5715e
        2   active empty
        3   active empty
        4 inactive empty
        5   active empty
        6   active cb6e8904-81ff-40da-a84a-07ab9ab5715e
        7   active cb6e8904-81ff-40da-a84a-07ab9ab5715e


    Examples:
        >>> type(parsed_result)
        <class 'insights.parsers.luksmeta.LuksMeta'>

        >>> parsed_result[0].index
        0

        >>> parsed_result[0].state
        'active'

        >>> parsed_result[4].state
        'inactive'

        >>> parsed_result[0].metadata is None
        True

        >>> parsed_result[1].metadata
        'cb6e8904-81ff-40da-a84a-07ab9ab5715e'
    """  # noqa

    def parse_content(self, content):
        if len(content) >= 1 and "Device is not initialized" in content[0]:
            raise SkipComponent

        # LUKS1 contains exactly 8 keyslots
        if len(content) != 8:
            raise SkipComponent

        for line in content:
            index, state, metadata = line.split()
            index = int(index)
            metadata = None if metadata == "empty" else metadata
            self[index] = KeyslotSpecification(index, state, metadata)
