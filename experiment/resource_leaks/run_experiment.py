import openpyxl
from pathlib import Path
import subprocess
import os
from sys import argv


def main():
    xlsx_file = Path('./experiment/resource_leaks', 'droidleaks.xlsx')
    wb_obj = openpyxl.load_workbook(xlsx_file)

    seen = set()

    # Read the active sheet:
    sheet = wb_obj.active

    rows = sheet.rows
    next(rows)
    next(rows)
    for row in rows:
        app = row[0].value.replace(' ', '-')
        curr_file = './experiment/resource_leaks/apks/' + app + "-rev-" + row[3].value + ".apk"
        if curr_file in seen:
            continue
        else:
            seen.add(curr_file)

        if os.path.exists(curr_file) and curr_file:
            cmd = make_cmd(curr_file)
            print(curr_file)
            print('Resource:', row[1].value, '\nsource method:', row[4].value, '\nsource file:', row[5].value)
            print('Our analysis output:')
            output = os.popen(cmd).read()
            print(output)
        else:
            print("File does not exist:", curr_file)


def make_cmd(filename):
    timeout = "3600" if len(argv) <= 2 else argv[2]
    return "./run.sh -a " + filename + " -p " + argv[1] + " -r -t " + timeout


if __name__ == '__main__':
    main()