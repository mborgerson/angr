#!/usr/bin/env python
"""
We want to have all available architectures registered as archinfo objects,
however we require a context to extract some details which incurs a high startup
cost.

To avoid this high startup cost and to support having all supported
architectures registered as archinfo classes, we generate arch class definitions
from pypcode defs offline using this script.

FIXME:
 - Definition consistency check test cases
 - Transfering memory space representation information (angr assumes vonneumman)
 - Transferring additional details (compiler specs etc)
"""
from archinfo.arch import register_arch, Arch, Endness, Register
from archinfo.tls import TLSArchInfo

import logging
import pypcode


l = logging.getLogger(__name__)

hdr = '''
###
### This file was automatically generated based on pypcode definitions.
###

from archinfo.arch import register_arch, Arch, Endness, Register
from archinfo.tls import TLSArchInfo

class ArchPcode(Arch):
    """
    A generic architecture for architectures supported by pypcode, but not yet
    explicitly defined in archinfo. Provides minimal architectural info like
    register file map, endianness, bit width, etc.
    """
    initial_sp = 0x7fff #??
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

'''

def create_archinfo_class_from_lang(lang:pypcode.ArchLanguage) -> str:
    """
    Construct an archinfo class definition from pypcode architecture definitions.
    """
    ctx = pypcode.Context(lang)
    archinfo_regs = {
        rname.lower(): Register(rname.lower(), r.size, r.offset)
            for rname, r in ctx.registers.items()
            }

    # Map subregisters
    # for reg_name, reg in list(archinfo_regs.items()):
    #     for subreg_name, subreg in list(archinfo_regs.items()):
    #         if (reg_name == subreg_name) \
    #            or not ((subreg.vex_offset >= reg.vex_offset) \
    #                    and ((subreg.vex_offset + subreg.size) \
    #                         <= (reg.vex_offset + reg.size))):
    #            continue
    #         # print('%s is subreg of %s' % (subreg_name, reg_name))
    #         reg.subregisters = reg.subregisters + \
    #                            subreg.subregisters + \
    #                            [(subreg_name, subreg.vex_offset - reg.vex_offset, subreg.size)]
    #         archinfo_regs.pop(subreg_name, None)

    # Get program counter register
    pc_offset = None
    pc_tag = lang.pspec.find('programcounter')
    if pc_tag is not None:
        pc_reg = pc_tag.attrib.get('register', None)
        if pc_reg is not None:
            # FIXME: Assumes RAM space
            pc_offset = ctx.registers[pc_reg].offset
            aliases = {'pc', 'ip'}
            aliases.discard(pc_reg.lower())
            archinfo_regs[pc_reg.lower()].alias_names = tuple(aliases)

    if pc_offset is None:
        l.warning('Unknown program counter register offset?')
        pc_offset = 0x80000000

    # Get stack pointer register
    sp_offset = None

    if len(lang.cspecs):
        def find_matching_cid(desired):
            for cid in lang.cspecs:
                if cid[0] == desired:
                    return cid
        cspec_id = find_matching_cid('default') \
                   or find_matching_cid('gcc') \
                   or list(lang.cspecs)[0]
        cspec = lang.cspecs[cspec_id]
        sp_tag = cspec.find('stackpointer')
        if sp_tag is not None:
            sp_reg = sp_tag.attrib.get('register', None)
            if sp_reg is not None:
                # FIXME: Assumes RAM space
                sp_offset = ctx.registers[sp_reg].offset

    if sp_offset is None:
        l.warning('Unknown stack pointer register offset?')
        sp_offset = 0x80000008

    bits = int(lang.size)
    archname = lang.id
    endness = {'little': 'Endness.LE', 'big': 'Endness.BE'}[lang.endian]
    def stringify_reg(r):
        return f"Register('{r.name}', {r.size}, {hex(r.vex_offset)}" \
            + ((', alias_names=' + str(r.alias_names)) if len(r.alias_names) else '') \
            + ")"
    reg_list_str = ",\n        ".join([stringify_reg(r) for r in archinfo_regs.values()])
    archname_san = ''.join([c if c.isalnum() else '_' for c in archname])
    classname = 'ArchPcode_' + archname_san
    return f"""class {classname}(ArchPcode):
    name = '{archname}'
    description = {repr(lang.description)}
    bits = {bits}
    ip_offset = {hex(pc_offset)}
    sp_offset = {hex(sp_offset)}
    instruction_endness = {endness}
    register_list = [
        {reg_list_str}
    ]

register_arch(['{archname.lower()}'], {bits}, {endness}, {classname})

"""

def main():
    import os.path
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'arch_def.py')
    with open(p, 'w') as f:
        f.write(hdr)
        langs = [lang for arch in pypcode.Arch.enumerate()
                         for lang in arch.languages]
        for i, lang in enumerate(langs):
            print('Generating arch definition for %s (%d of %d)' % (lang.id, i+1, len(langs)))
            cdef = create_archinfo_class_from_lang(lang)
            f.write(cdef)

if __name__ == '__main__':
    main()
