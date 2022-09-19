"""
luksmeta - command ``luksmeta show -d``
=======================================
This class provides parsing for the output of luksmeta <device_name>.
"""

from insights import parser, Parser
from insights.specs import Specs


class KeyslotSpecification:
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
class LuksMeta(Parser):
    """
    Sample input data is in the format::

        LUKS header information
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

        >>> parsed_result.keyslots[0].index
        0

        >>> parsed_result.keyslots[0].state
        'active'

        >>> parsed_result.keyslots[4].state
        'inactive'

        >>> parsed_result.keyslots[0].metadata is None
        True

        >>> parsed_result.keyslots[1].metadata
        'cb6e8904-81ff-40da-a84a-07ab9ab5715e'


    Attributes:
        keyslots(dict): A list of 8 KeyslotSpecification objects, describing
        every LUKS keyslot. The KeyslotSpecification contains the index, state
        and metadata fileds. Metadata field stores the UUID of the application
        that has stored metadata in the keyslot.
    """  # noqa

    def __init__(self, context):
        self.keyslots = [None] * 8
        super(LuksMeta, self).__init__(context)

    def parse_content(self, content):
        for line in content:
            index, state, metadata = line.split()
            index = int(index)
            metadata = None if metadata == "empty" else metadata
            self.keyslots[index] = KeyslotSpecification(index, state, metadata)
