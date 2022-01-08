import wfuzz
import pdb
from collections import defaultdict


RESULT_FILTER_CEILING = 3


def main():

    print("-------")
    print("rapfuzz")
    print("-------")
    print()

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


if __name__ == "__main__":
    main()
