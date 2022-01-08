import os
import sys
import pdb
import datetime
import argparse
from urllib.parse import urlparse
from collections import defaultdict

import wfuzz


RESULT_FILTER_CEILING = 100


def fuzz(urlList, wordlist, outputDir="."):

    for url in urlList:

        u = urlparse(url)
        scheme = u.scheme
        netloc = u.netloc
        path = u.path.replace("/", "_")
        now = (
            str(datetime.datetime.now())
            .replace(" ", "_")
            .replace(":", "-")
            .split(".")[0]
        )
        logFileName = f"rapfuzz.log.{scheme}_{netloc}{path}.{now}"

        with open(logFileName, "w") as logFile:

            def log(logString=""):
                print(logString)
                logFile.write(f"{logString}\n")

            codeList = [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
            payloads = [("file", dict(fn=wordlist))]
            concurrent = 40
            headers = [("X-Hackerone", "rappie")]
            # proxies = [("localhost", 8080, "HTTP")]
            proxies = []

            log(f"Date: {now}")
            log(f"URL: {url}")
            log(f"Wordlist: {wordlist}")
            log(f"Show codes: {codeList}")
            log()

            resultData = defaultdict(list)
            counter = 0

            with wfuzz.FuzzSession(
                url=url,
                payloads=payloads,
                concurrent=concurrent,
                headers=headers,
                proxies=proxies,
                scanmode=True,  # ignore connection errors
            ) as session:
                for resultLine in session.fuzz():

                    if counter % 1000 == 0:
                        print(".", end="", flush=True)

                    if resultLine.code in codeList:
                        resultData[resultLine.code].append(resultLine)

                    counter += 1

            print()
            print()

            for code, resultList in resultData.items():

                if len(resultList) >= RESULT_FILTER_CEILING:
                    log(f"too many results for code: {code} ({len(resultList)})")

                else:
                    for resultLine in resultList:
                        log(resultLine)

                log()


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

    # Append 'FUZZ' if nessecary
    fixedUrlList = []
    for url in urlList:
        if "FUZZ" not in url:
            if not url.endswith("/"):
                url += "/"
            url += "FUZZ"
        fixedUrlList.append(url)
    urlList = fixedUrlList

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
