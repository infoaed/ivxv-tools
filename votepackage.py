#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Märt Põder

import argparse
import base64
import json
import re
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

from pyasice import Container


def timestamp(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt.strftime("%Y%m%d%H%M%S000+0300")


def personal_code(bdoc):
    sig = next(Container(BytesIO(bdoc)).iter_signatures())
    serial = (sig.get_certificate().asn1.subject.native["serial_number"])
    return re.search(r"\d{11}", serial).group(0)


def produce_votes_zip(input_dir, output_zip):
    dirs = set()
    voters = dict()

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as z:

        count = 0
        for file in sorted(Path(input_dir).glob("*.json")):
            count += 1
            data = json.loads(file.read_text())

            ts = timestamp(data["BallotMoment"])

            vote = base64.b64decode(data["result"]["Vote"])
            ocsp = base64.b64decode(data["result"]["Qualification"]["ocsp"])
            tspreg = base64.b64decode(data["result"]["Qualification"]["tspreg"])

            voter = personal_code(vote)
            voters[voter] = True
            ext = data["result"]["Type"].lower()

            print(f"{count: 3d}. {voter} {data["BallotMoment"]}")

            if voter not in dirs:
                z.mkdir(voter)
                dirs.add(voter)

            prefix = f"{voter}/{ts}"

            z.writestr(f"{prefix}.{ext}", vote)
            z.writestr(f"{prefix}.ocsp", ocsp)
            z.writestr(f"{prefix}.tspreg", tspreg)
            z.writestr(f"{prefix}.version", b"0")

    print(f"Created {output_zip} with {count} ballots from {len(voters)} voters")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir")
    parser.add_argument("output_zip")
    args = parser.parse_args()

    produce_votes_zip(args.input_dir, args.output_zip)


if __name__ == "__main__":
    main()
