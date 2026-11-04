#!/usr/bin/env python3
"""Apply the small command-boundary hook to the checksum-pinned FRR 10.0 tree."""
from pathlib import Path


def replace(path, old, new, count=1):
    text = path.read_text()
    if text.count(old) != count:
        raise SystemExit(f'{path}: expected {count} matching patch locations')
    path.write_text(text.replace(old, new))


main = Path('vtysh/vtysh_main.c')
replace(main, '#include "vtysh/vtysh_user.h"', '#include "vtysh/vtysh_user.h"\n#include "vtysh/twinet_collection.h"')
replace(main, 'vtysh_execute(line_read);', 'collected_execute(line_read, 1, "interactive");')
replace(main, 'vtysh_execute_no_pager(cmd->line)', 'collected_execute(cmd->line, 0, "argument")', 2)
replace(main, 'vtysh_execute_no_pager(cmdnow)', 'collected_execute(cmdnow, 0, "argument")')
replace(main, 'struct option longopts[] = {', 'struct option longopts[] = {\n\t{"twinet-collection-version", no_argument, NULL, 1100},')
replace(main, '\t\tswitch (opt) {', '\t\tswitch (opt) {\n\t\tcase 1100:\n\t\t\tputs("1");\n\t\t\treturn 0;')
source = Path('vtysh/vtysh.c')
replace(source, 'static int vtysh_exit(struct vty *vty)', 'extern void twinet_collection_end(int result);\n\nstatic int vtysh_exit(struct vty *vty)')
replace(source, 'if (vty->node == VIEW_NODE || vty->node == ENABLE_NODE)\n\t\texit(0);', 'if (vty->node == VIEW_NODE || vty->node == ENABLE_NODE) {\n\t\ttwinet_collection_end(CMD_SUCCESS);\n\t\texit(0);\n\t}')
