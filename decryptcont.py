#!/usr/bin/env python3

import argparse
import base64
import json
import re
from pathlib import Path

from pyasice import Container
from pyivxv.crypto.keys import PublicKey
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.encoding.message import decode_from_point


def ballot_from_bdoc(path):
    with open(path, "rb") as f:
        c = Container(f)

        name = c.data_file_names[0]
        if ".question-" in name and name.endswith(".ballot"):
            return name, c.open_file(name).read()

    raise ValueError("ballot not found in container")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("json_dir")
    parser.add_argument("bdoc")
    args = parser.parse_args()

    ballot_name, ballot_bytes = ballot_from_bdoc(args.bdoc)
    ballot_b64 = base64.b64encode(ballot_bytes).decode()

    match = None

    for jf in Path(args.json_dir).glob("*.json"):
        data = json.loads(jf.read_text())

        for key, value in data.items():
            if key.endswith(".ballot") and value == ballot_b64:
                match = data
                break

        if match:
            break

    if not match:
        raise SystemExit("Matching JSON not found")

    m = re.fullmatch(r"(.+)\.question-(.+)\.ballot", ballot_name)
    round = m.group(1)

    with open(f"keys/{round}_pub.pem", "rb") as f:
        pk = PublicKey.from_public_bytes(f.read())

    r = int.from_bytes(
        base64.b64decode(match["Ephemeral"]),
        byteorder="big",
    )

    ct = ElGamalCiphertext.from_bytes(ballot_bytes)
    unblinded = ct.unblind(pk.H, r=r)

    decoded = decode_from_point(
        unblinded,
        pk.curve,
    ).decode()

    print(f"{decoded} -- {jf.parts[-1]}")


if __name__ == "__main__":
    main()
