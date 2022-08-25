"""
LUKS_Dump - command ``cryptsetup luksDump``
============================================================
This class provides parsing for the output of cryptsetup luksDump
<device_name>. Outputs from LUKS1 and LUKS2 are supported.
"""

from insights import parser, Parser
from insights.specs import Specs
import string

from insights.parsr import Literal, AnyChar, Char, Opt, String, WS, HangingString, WithIndent, Many


def convert_type(section):
    section[1]["type"] = section[0][1]
    return [section[0][0], section[1]]


def convert_status(section):
    section[2]["status"] = section[1]
    return [section[0], section[2]]


value_chars = set(string.printable) - set("\n\r")

FirstLine = Literal("LUKS header information", value="header") << AnyChar.until(Char("\n")) + Opt(Many(Char("\n")))
FirstIndent = Literal("  ")
# we need to replace the \t by 8 spaces in the input,
# otherwise WithIndent does not work properly
# SecondIndent = Literal("\t")
SecondIndent = Literal(" " * 8)

Key = String(value_chars - set(":")) << Char(":") % "Key"
Value = WS >> HangingString(value_chars) % "Value"

MultilineContinuation = Many((Char("\n") + Literal(" " * 15) + SecondIndent) >> String(value_chars))
Value1 = WS >> String(value_chars) + Opt(MultilineContinuation).map(lambda x: "".join(x)) << Char("\n")
Value1 = Value1.map(lambda x: ("".join(x)).strip())

ZeroLevelKVPair = Key + Value1
FirstLevelKVPair = FirstIndent >> Key + Value1
SecondLevelKVPair = SecondIndent >> WithIndent(Key + Value)

LUKS2SectionName = Key << Char("\n")
LUKS2SectionEntry = (FirstLevelKVPair + Many(SecondLevelKVPair).map(dict)).map(convert_type)
LUKS2Section = LUKS2SectionName + Many(LUKS2SectionEntry).map(dict) << Opt(Many(Char("\n")))
LUKS2Body = Many(LUKS2Section).map(dict)

LUKS1Section = ZeroLevelKVPair + Many(SecondLevelKVPair).map(dict) << Opt(Many(Char("\n")))
LUKS1Body = Many(LUKS1Section.map(convert_status)).map(dict)

KVBlock = Many(Key + Value1).map(dict)
LUKS_Header = (FirstLine + KVBlock) << Opt(Many(Char("\n")))
LUKS_Header = LUKS_Header.map(lambda x: dict([x]))


@parser(Specs.cryptsetup_luksDump)
class LUKS_Dump(Parser):
    """
    Sample input data is in the format::

        LUKS header information
        Version:       	2
        Epoch:         	6
        Metadata area: 	16384 [bytes]
        Keyslots area: 	16744448 [bytes]
        UUID:          	cfbcc942-e06b-4c4a-952f-e9c9b2011c27
        Label:         	(no label)
        Subsystem:     	(no subsystem)
        Flags:       	(no flags)

        Data segments:
          0: crypt
                offset: 16777216 [bytes]
                length: (whole device)
                cipher: aes-xts-plain64
                sector: 4096 [bytes]

        Keyslots:
          0: luks2
                Key:        512 bits
                Priority:   normal
                Cipher:     aes-xts-plain64
                Cipher key: 512 bits
                PBKDF:      argon2id
                Time cost:  7
                Memory:     1048576
                Threads:    4
                AF stripes: 4000
                AF hash:    sha256
                Area offset:32768 [bytes]
                Area length:258048 [bytes]
                Digest ID:  0
        Tokens:
          0: systemd-tpm2
                Keyslot:    2
        Digests:
          0: pbkdf2
                Hash:       sha256
                Iterations: 129774

    Examples:
        >>> type(ros_input)
        <class 'insights.parsers.ros_config.RosConfig'>
        >>> ros_input.rules[0]['allow_disallow']
        'disallow'
        >>> ros_input.rules[0]['hostlist']
        ['.*']
        >>> ros_input.rules[0]['operationlist']
        ['all']
        >>> ros_input.specs[0].get('state')
        'mandatory on'
        >>> ros_input.specs[0].get('metrics')['mem.util.used']
        []
        >>> ros_input.specs[0].get('metrics')['kernel.all.cpu.user']
        []
        >>> ros_input.specs[0].get('logging_interval')
        'default'

        >>> type(dump)
        Out[6]: insights.parsers.cryptsetup_luksDump.LUKS_Dump

        >>> dump.dump["header"]
        {'Version': '2',
         'Epoch': '6',
         'Metadata area': '16384 [bytes]',
         'Keyslots area': '16744448 [bytes]',
         'UUID': 'cfbcc942-e06b-4c4a-952f-e9c9b2011c27',
         'Label': '(no label)',
         'Subsystem': '(no subsystem)',
         'Flags': '(no flags)'}

        >>> dump.dump["Keyslots"]["0"]
        {'Key': '512 bits',
         'Priority': 'normal',
         'Cipher': 'aes-xts-plain64',
         'Cipher key': '512 bits',
         'PBKDF': 'argon2id',
         'Time cost': '7',
         'Memory': '1048576',
         'Threads': '4',
         'AF stripes': '4000',
         'AF hash': 'sha256',
         'Area offset': '32768 [bytes]',
         'Area length': '258048 [bytes]',
         'Digest ID': '0',
         'type': 'luks2'}

        >>> dump.dump["Tokens"]["0"]["type"]
        'systemd-tpm2'


    Attributes:
        dump(dict of dicts): A top level dict containing the dictionaries
            representing the header, data segments, keyslots, digests
            and tokens.

    """
    def parse_dump(self, text):
        self.dump = None
        header = LUKS_Header(text)

        if header["header"]["Version"] == "1":
            header, body = (LUKS_Header + LUKS1Body)(text)
            return header | body
        elif header["header"]["Version"] == "2":
            header, body = (LUKS_Header + LUKS2Body)(text)
            return header | body

    def parse_content(self, content):
        try:
            self.dump = self.parse_dump("\n".join(content).replace("\t", " "*8) + "\n")
        except:
            self.dump = None
