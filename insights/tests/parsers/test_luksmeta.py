import doctest
import pytest

from insights import SkipComponent
from insights.parsers import luksmeta
from insights.tests import context_wrap


LUKSMETA_OUTPUT = """0   active empty
1   active cb6e8904-81ff-40da-a84a-07ab9ab5715e
2   active empty
3   active empty
4 inactive empty
5   active empty
6   active cb6e8904-81ff-40da-a84a-07ab9ab5715e
7   active cb6e8904-81ff-40da-a84a-07ab9ab5715e
"""  # noqa

LUKSMETA_NOT_FOUND = "bash: luksmeta: command not found..."
LUKSMETA_NOT_INITIALIZED = "Device is not initialized (./luks1)"
LUKSMETA_BAD_DEVICE = "./luks2 (LUKS2) is not a LUKSv1 device"


def test_luksmeta():
    luksmeta_parsed = luksmeta.LuksMeta(context_wrap(LUKSMETA_OUTPUT))

    with pytest.raises(SkipComponent):
        luksmeta.LuksMeta(context_wrap(LUKSMETA_NOT_FOUND))

    with pytest.raises(SkipComponent):
        luksmeta.LuksMeta(context_wrap(LUKSMETA_NOT_INITIALIZED))

    with pytest.raises(SkipComponent):
        luksmeta.LuksMeta(context_wrap(LUKSMETA_BAD_DEVICE))

    assert len(luksmeta_parsed) == 8

    for i in range(8):
        assert luksmeta_parsed[i].index == i

    assert str(luksmeta_parsed[0]) == "Keyslot on index 0 is 'active' with no embedded metadata"
    assert str(luksmeta_parsed[1]) == "Keyslot on index 1 is 'active' with metadata stored by application with UUID 'cb6e8904-81ff-40da-a84a-07ab9ab5715e'"

    assert luksmeta_parsed[0].state == "active"
    assert luksmeta_parsed[4].state == "inactive"

    assert luksmeta_parsed[0].metadata is None
    assert luksmeta_parsed[1].metadata is not None
    assert luksmeta_parsed[1].metadata == "cb6e8904-81ff-40da-a84a-07ab9ab5715e"


def test_doc_examples():
    env = {
            'parsed_result': luksmeta.LuksMeta(context_wrap(LUKSMETA_OUTPUT)),
          }
    failed, total = doctest.testmod(luksmeta, globs=env)
    assert failed == 0
