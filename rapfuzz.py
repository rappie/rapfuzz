import sys
import pdb
import argparse
from collections import defaultdict

import wfuzz


RESULT_FILTER_CEILING = 3


def fuzz(args):

    url = "http://testphp.vulnweb.com/FUZZ"
    sc = [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
    hc = []
    payloads = [("file", dict(fn="wordlist.txt"))]

    resultData = defaultdict(list)

    with wfuzz.FuzzSession(url=url, payloads=payloads) as session:
        for resultLine in session.fuzz(sc=sc, hc=hc):
            resultData[resultLine.code].append(resultLine)

    for code, resultList in resultData.items():

        if len(resultList) >= RESULT_FILTER_CEILING:
            print(f"too many results for code: {code} ({len(resultList)})")

        else:
            for resultLine in resultList:
                print(resultLine)

        print()


def parseArgs():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-U", "--url-file", help="Filename with url(s)")
    parser.add_argument("-w", "--wordlist", help="Wordlist to use", required=True)
    parser.add_argument("-o", "--output-file", help="Filename to write output to")
    return parser.parse_args()


def checkArgs(args):

    print(args)

    print("check ok")
    return True


if __name__ == "__main__":

    print("-------")
    print("rapfuzz")
    print("-------")
    print()

    args = parseArgs()
    if not checkArgs(args):
        sys.exit(1)
    fuzz(args)
