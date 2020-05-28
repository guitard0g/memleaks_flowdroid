import openpyxl
from pathlib import Path
import subprocess
import os
from sys import argv


def main():
    for filename in os.listdir("./experiment/memory_leaks/apks"):
        print(filename)
        curr_file = './experiment/memory_leaks/apks/' + filename
        cmd = make_cmd(curr_file)
        output = os.popen(cmd).read()
        print(output)


def make_cmd(filename):
    timeout = "3600" if len(argv) <= 2 else argv[2]
    return "./run.sh -a " + filename + " -p " + argv[1] + " -t " + timeout


if __name__ == '__main__':
    main()