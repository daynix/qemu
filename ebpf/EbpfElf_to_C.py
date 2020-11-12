#!/usr/bin/python3

import sys
import argparse

def process_file(filename, prog_name):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        with open("%s.h" % prog_name, 'w') as w:

            w.write('#ifndef %s\n' % prog_name.upper())
            w.write('#define %s\n\n' % prog_name.upper())

            w.write("uint8_t data_%s[] = {\n" % prog_name)

            data = f.read(8)
            while data:
                w.write("    " + ", ".join("0x%02x" % x for x in data) + ",\n")
                data = f.read(8)

            w.write('};\n\n')

            w.write('#endif /* %s */\n' % prog_name.upper())

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert eBPF ELF to C header. '
                    'Section name will be used in C namings.')
    parser.add_argument('--file', '-f', nargs=1, required=True,
                        help='eBPF ELF file')
    parser.add_argument('--section', '-s', nargs=1, required=True,
                        help='section in ELF with eBPF program.')
    args = parser.parse_args()
    sys.exit(process_file(args.file[0], args.section[0]))
