import pytest

from insights import SkipComponent
from insights.parsers.cryptsetup_luksDump import LuksDump
from insights.combiners.cryptsetup import luks1_block_devices
from insights.tests import context_wrap

LUKS1_DUMP = """LUKS header information for luks1

Version:       	1
Cipher name:   	aes
Cipher mode:   	xts-plain64
Hash spec:     	sha256
Payload offset:	4096
MK bits:       	512
MK digest:     	ca fe ba be df 8c c4 b4 b8 0a cc dd 98 b5 d8 64 3a 95 3e 9e 
MK salt:       	ca fe ba be 04 3b 77 d8 ff 08 1e 0a 41 68 45 a5 
               	ca fe ba be 7b 3f a9 69 9c 9b 51 24 58 47 8d a2 
               	ca fe ba be 7b 3f a9 69 9c 9b 51 24 58 47 8d a2 
               	ca fe ba be 7b 3f a9 69 9c 9b 51 24 58 47 8d a2 
               	ca fe ba be 7b 3f a9 69 9c 9b 51 24 58 47 8d a2 
               	ca fe ba be 7b 3f a9 69 9c de ad be ef 
MK iterations: 	106562
UUID:          	263902da-5f0c-43a9-82eb-cc6f14d90448

Key Slot 0: ENABLED
	Iterations:         	2099250
	Salt:               	de ad be ef 
	Salt:               	ca fe ba be a1 f3 ae cb 4a 3f f0 2d de ad be ef 
	                      	de ad be ef 
	Key material offset:	8
	AF stripes:            	4000
Key Slot 1: ENABLED
	Iterations:         	1987820
	Salt:               	ca fe ba be f2 b7 7d f3 29 c2 c8 80 de ad be ef 
	                      	ca fe ba be 9f a1 87 07 c6 4f aa cd de ad be ef 
	                      	ca fe ba be 9f a1 87 07 c6 4f aa de ad be ef 
	Key material offset:	512
	AF stripes:            	4000
Key Slot 2: ENABLED
	Iterations:         	2052006
	Salt:               	ca fe ba be 47 94 e7 40 22 c1 bb 4a de ad be ef 
	                      	ca fe ba be 52 e8 8d 70 b2 1e 9d 47 de ad be ef 
	Key material offset:	1016
	AF stripes:            	4000
Key Slot 3: DISABLED
Key Slot 4: DISABLED
Key Slot 5: DISABLED
Key Slot 6: DISABLED
Key Slot 7: DISABLED
"""  # noqa

LUKS2_DUMP = """LUKS header information
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
	Salt:       ca fe ba be fe 1c 90 d8 2a 35 b2 b2 de ad be ef 
	            ca fe ba be b2 dd 45 9e ed 9a 33 b2 de ad be ef 
                    de ad be ef 
	AF stripes: 4000
	AF hash:    sha256
	Area offset:32768 [bytes]
	Area length:258048 [bytes]
	Digest ID:  0
  1: luks2
	Key:        512 bits
	Priority:   normal
	Cipher:     aes-xts-plain64
	Cipher key: 512 bits
	PBKDF:      argon2id
	Time cost:  7
	Memory:     1048576
	Threads:    4
	Salt:       ca fe ba be c1 94 15 86 2a e9 26 f8 de ad be ef 
	            ca fe ba be 05 2d 80 c9 56 e8 4d 6f de ad be ef 
	AF stripes: 4000
	AF hash:    sha256
	Area offset:290816 [bytes]
	Area length:258048 [bytes]
	Digest ID:  0
  2: luks2
	Key:        512 bits
	Priority:   normal
	Cipher:     aes-xts-plain64
	Cipher key: 512 bits
	PBKDF:      pbkdf2
	Hash:       sha512
	Iterations: 1000
	Salt:       ca fe ba be d7 8f a6 de a0 cb a4 d1 de ad be ef 
	            ca fe ba be fb 53 43 06 e8 83 90 93 de ad be ef 
	AF stripes: 4000
	AF hash:    sha512
	Area offset:548864 [bytes]
	Area length:258048 [bytes]
	Digest ID:  0
Tokens:
  0: systemd-tpm2
        tpm2-pcrs:  7
        tpm2-bank:  sha256
        tpm2-primary-alg:  ecc
        tpm2-blob:  00 9e 00 20 bd 97 78 70 3f 3a 5b 93 d4 8f dc ed
                    10 16 b2 ce f5 f7 a2 c8 63 f6 19 12 63 7a f2 94
                    26 f1 b6 1b 00 10 2e 36 26 c1 3b f7 1e 8d 86 55
        tpm2-policy-hash:
                    df 06 80 28 e7 67 b1 d0 34 f4 de 1b 8e ac 33 5a
                    df 06 80 28 e7 67 b1 d0 34 f4 de 1b 8e ac 33 5a
	Keyslot:    2
Digests:
  0: pbkdf2
	Hash:       sha256
	Iterations: 129774
	Salt:       ca fe ba be e0 65 83 82 35 03 29 56 de ad be ef 
	            ca fe ba be de 69 39 97 d5 b3 ac c4 de ad be ef 
                    de ad be ef 
	Digest:     ca fe ba be 9d 46 9b 0f 3a 0f 57 13 de ad be ef 
	            ca fe ba be ed 7d 09 2c 3d b6 fa f4 de ad be ef 
"""  # noqa


def test_luks1_devices_listing():
    luks1_device = LuksDump(context_wrap(LUKS1_DUMP))
    luks2_device = LuksDump(context_wrap(LUKS2_DUMP))
    luks_devices = luks1_block_devices([luks1_device, luks2_device])

    # only the LUKS1 device's UUID is returned
    assert luks_devices == ["/dev/disk/by-uuid/263902da-5f0c-43a9-82eb-cc6f14d90448"]

    with pytest.raises(SkipComponent):
        luks_devices = luks1_block_devices([])

    with pytest.raises(SkipComponent):
        luks_devices = luks1_block_devices([luks2_device])
