import os
import sys
import pdb
import argparse
from collections import defaultdict

import wfuzz


RESULT_FILTER_CEILING = 3


def fuzz(urlList, wordlist, outputDir):

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
    parser.add_argument("-o", "--output-dir", help="Directory to write output to")
    args = parser.parse_args()

    if args.url:
        urlList = [args.url]
    else:
        if not os.path.exists(args.url_file):
            raise Exception(f"URL file path does not exist: {args.url_file}")
        with open(args.url_file, "r") as urlFile:
            urlList = [k.strip() for k in urlFile.readlines() if k.strip() != ""]

    # Append '/FUZZ' if nessecary
    urlList = list(map(lambda x: x if "FUZZ" in x else f"{x}/FUZZ", urlList))

    if not os.path.exists(args.wordlist):
        raise Exception(f"Wordlist file path does not exist: {args.wordlist}")

    wordlist = args.wordlist

    if args.output_dir:
        if not os.path.exists(args.output_dir):
            raise Exception(f"Output directory does not exist: {args.output_dir}")

    outputDir = args.output_dir

    return urlList, wordlist, outputDir


if __name__ == "__main__":

    print("-------")
    print("rapfuzz")
    print("-------")
    print()

    args = parseArgs()
    fuzz(*args)
