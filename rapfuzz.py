import wfuzz
import pdb
from collections import defaultdict
import pprint

pp = pprint.PrettyPrinter(indent=2)


"""
        resultLine.description
        resultLine.history.method
        resultLine.code
        resultLine.chars
        resultLine.lines
        resultLine.words
        resultLine.md5
        resultLine.history.raw_content
"""

if __name__ == "__main__":
    print("rapfuzz")
    print("-------")
    print()

    RESULT_FILTER_CEILING = 3

    url = "http://testphp.vulnweb.com/FUZZ"
    # hc = [400, 404]
    hc = []
    payloads = [("file", dict(fn="wordlist.txt"))]

    resultData = defaultdict(list)

    with wfuzz.FuzzSession(url=url, payloads=payloads) as session:
        for resultLine in session.fuzz(hc=hc):

            resultData[resultLine.code].append(resultLine)

            # print(resultLine)

        # pdb.set_trace()
        # pass

    # print(len(resultData["200"]))
    # pdb.set_trace()

    # pp.pprint(resultData)
    for code, resultList in resultData.items():

        if len(resultList) >= RESULT_FILTER_CEILING:
            print(f"too many results for code: {code} ({len(resultList)})")

        else:
            for resultLine in resultList:
                print(resultLine)

        print()
