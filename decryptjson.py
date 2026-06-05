#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Märt Põder

import argparse
import base64
import json
import re

from pyivxv.crypto.keys import PublicKey
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.encoding.message import decode_from_point


def main():
    parser = argparse.ArgumentParser(
        description="Decode and unblind an IVXV ballot from a JSON-RPC response."
    )
    parser.add_argument(
        "json_file",
        help="JSON file containing Ephemeral and *.question-*.ballot fields",
    )
    args = parser.parse_args()

    with open(args.json_file, encoding="utf-8") as f:
        data = json.load(f)

    ephemeral = data["Ephemeral"]

    for key, ballot_b64 in data.items():
        m = re.fullmatch(r"(.+)\.question-(.+)\.ballot", key)
        if m:
            round = m.group(1)
            question = m.group(2)
            break
    else:
        raise ValueError("*.question-*.ballot field not found")

    with open(f"keys/{round}_pub.pem", "rb") as f:
        pk = PublicKey.from_public_bytes(f.read())

    r = int.from_bytes(base64.b64decode(ephemeral), byteorder="big")
    ballot = base64.b64decode(ballot_b64)

    ct = ElGamalCiphertext.from_bytes(ballot)
    unblinded = ct.unblind(pk.H, r=r)
    decoded = decode_from_point(unblinded, pk.curve).decode()

    print(f"{decoded} ({round})")


if __name__ == "__main__":
    main()
