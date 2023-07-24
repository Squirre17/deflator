import angr
import networkx as nx

from ptrlib                                    import ELF
from loguru                                    import logger
from pprint                                    import pprint
from angr.knowledge_plugins.functions.function import Function
from cle.backends.elf.symbol                   import ELFSymbol

import matplotlib.pyplot as plt
import angrutils
from angr.analyses.decompiler.utils import to_ail_supergraph

# cfg fast没考虑上下文关系 而cfg emulated考虑了
# CFGFast是通过静态分析获得CFG，CFGEmulated是通过动态符号执行获得更加准确的CFG
def render_graph(path: str, funcsym: str, outfilename: str) -> None:
    '''
    render a graph png picture
    '''
    proj = angr.Project(path, load_options={
        "auto_load_libs" : False
    })
    fnsym: ELFSymbol = proj.loader.main_object.get_symbol(funcsym)
    cfgfast: angr.analyses.CFGFast = proj.analyses.CFGFast(
        normalize=True, force_complete_scan=False
    )

    target_fn: Function = cfgfast.functions.get(fnsym.rebased_addr)

    angrutils.plot_common(
        target_fn.transition_graph, outfilename
    )  
    logger.info(f"{outfilename} render successfully")

def render_cfg(path: str, funcsym: str, outfilename: str="cp.cfg") -> None:
    '''
    render a cfg png picture
    '''
    proj = angr.Project(path, load_options={
        "auto_load_libs" : False
    })
    fnsym: ELFSymbol = proj.loader.main_object.get_symbol(funcsym)
    start_state = proj.factory.blank_state(addr=fnsym.rebased_addr)
    cfgemu: angr.analyses.CFGEmulated = proj.analyses.CFGEmulated(
        fail_fast=True,
        starts=[fnsym.rebased_addr], 
        initial_state=start_state
    )
    angrutils.plot_cfg(
        cfgemu, 
        outfilename, 
        asminst=True, 
        remove_imports=True, 
        remove_path_terminator=True
    )  
    logger.info("cfg render successfully")

def main():
    origin  = "/home/squ/proj/deflator/flat_control_flow/samples/bin/check_passwd_x8664_flat"
    recover = "/home/squ/proj/deflator/flat_control_flow/samples/bin/check_passwd_x8664_flat_recovered"
    render_cfg(origin,  "check_password", "cp.org")
    render_cfg(recover,  "check_password", "cp.rec")


main()











