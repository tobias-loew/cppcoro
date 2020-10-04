import os
import re

for root, dirs, files in os.walk("."):
    for filename in files:
        if filename[-1] == "~":
            continue
        if filename[0] == ".":
            continue
        if "processedincludes" in filename:
            continue

        fullfilename = os.path.join(root, filename)
        modifiedfilename = (os.path.splitext(fullfilename)[0]+
                "_processedincludes"+
                os.path.splitext(fullfilename)[1])

        print("{} to {}".format(fullfilename, modifiedfilename))
        lines = open(fullfilename).readlines()
        processedinclude = True
        while processedinclude:
            print("starting include cycle")
            processedinclude = False
            newlines = []
            for line in lines:
                if m := re.match(r"#include <cppcoro/([^>]*)>", line):
                    includedfilename = m.groups()[0]
                    print("including {}".format(includedfilename))
                    newlines += open(includedfilename).readlines()
                    print("include done")
                    processedinclude = True
                else:
                    newlines.append(line)

            lines = newlines
        open(modifiedfilename, "w").writelines(lines)

