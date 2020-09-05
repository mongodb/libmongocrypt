lines = []
for line in open ("README.md", "r"):
    line = line.replace("\"", "'")
    lines.append("\"" + line[:-1] + "\\n\"")

with open ("HELP.autogen", "w") as out:
    out.write ("\n".join(lines))
