#!/usr/bin/env python3

import sys
sys.path.append("..")

import argparse
import angr
import pyvex
import claripy
import struct
import loguru
import pdb
import capstone
import copy
from collections import defaultdict
import networkx

import am_graph
from util import *
from typing import List

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)
    
# @brief: 如果是真实块(预分发器的前驱) 就加入relevant_nodes 
#         如果是 序言块 返回块和 预分配器块 就跳过
#         其他的都是子分发器 nop掉
def get_relevant_nop_nodes(supergraph: networkx.DiGraph, pre_dispatcher_node, prologue_node, retn_node):
    # relevant_nodes = list(supergraph.predecessors(pre_dispatcher_node))
    relevant_nodes = []
    nop_nodes = []
    for node in supergraph.nodes():
        # 就是找预分发器的前驱 
        # supergraph.predecessors(pre_dispatcher_node)
        if supergraph.has_edge(node, pre_dispatcher_node) and node.size > 8:
            # XXX: use node.size is faster than to create a block
            relevant_nodes.append(node)
            continue
        if node.addr in (prologue_node.addr, retn_node.addr, pre_dispatcher_node.addr):
            continue
        nop_nodes.append(node)
    return relevant_nodes, nop_nodes


def symbolic_execution(project: angr.Project, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):

    def retn_procedure(state: angr.sim_state.SimState):
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)# 解除对当前ip的hook 也就是call的地址
        return

    def statement_inspect(state):
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions
        )
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            '''
    ip  --> 400874:       81 7d e8 a1 01 00 00    cmp    DWORD PTR [rbp-0x18],0x1a1
            ---------------------------------------------------------------------
    ITE --> 40087b:       0f 44 c1                cmove  eax,ecx
            40087e:       89 45 e4                mov    DWORD PTR [rbp-0x1c],eax
            400881:       e9 15 01 00 00          jmp    40099b <check_password+0x46b>
            '''
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addrs is not None:# 有call指令 
        skip_length = 4
        if project.arch.name in ARCH_X86:
            skip_length = 5

        # 对于所有的call指令 全部跳过 啥都不做 不太懂？？
        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    state: angr.sim_state.SimState = project.factory.blank_state(
        addr=start_addr, 
        remove_options={
            angr.sim_options.LAZY_SOLVES
        }
    )

    # 通过调用 state.inspect.b() 方法，为语句检查事件 ('statement') 注册一个回调函数 
    # statement事件: An IR statement is being translated.
    # ref: https://docs.angr.io/en/latest/core-concepts/simulation.html#breakpoints
    # 每次遇到ITE的statement就进行值的替换 比如cmov 替换掉cond
    if inspect:
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect
        )
    sm = project.factory.simulation_manager(state)
    sm.step()# 我疑惑step好久停？
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                # 经过调试 这里就是某个real block的开头地址
                return active_state.addr
        sm.step()

    return None


def main():
    parser = argparse.ArgumentParser(description="deflat control flow script")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument(
        "--addr", help="address of target function in hex format")
    args = parser.parse_args()

    if args.file is None or args.addr is None:
        parser.print_help()
        sys.exit(0)

    filename = args.file
    start = int(args.addr, 16)

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    # Generate a static CFG => cfg = p.analyses.CFGFast()
    # do normalize to avoid overlapping blocks, disable force_complete_scan to avoid possible "wrong" blocks
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    # ref: https://docs.angr.io/en/latest/analyses/cfg.html#function-manager
    target_function = cfg.functions.get(start)
    # A super transition graph is a graph that looks like IDA Pro's CFG
    # transition graph是一个做函数内部控制流可视化的有向图 (类型:networkx.DiGraph)
    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    # get prologue_node and retn_node
    prologue_node = None
    for node in supergraph.nodes():
        # 入度为0是序言
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        # 出度为0是返回块
        if supergraph.out_degree(node) == 0 and len(node.out_branches) == 0:
            retn_node = node

    if prologue_node is None or prologue_node.addr != start:
        print("Something must be wrong...")
        sys.exit(-1)

    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]
    # 主分发器有两个前驱 一个是从序言块来的  一个是从最底层的预处理器来的
    for node in supergraph.predecessors(main_dispatcher_node):
        if node.addr != prologue_node.addr:
            pre_dispatcher_node = node # 预处理器/预分发器 怎么叫都行
            break

    # 获取supergraph中的真实块和 nop块(也就是子分发器)
    relevant_nodes, nop_nodes = get_relevant_nop_nodes(
        supergraph, pre_dispatcher_node, prologue_node, retn_node
    )
    print('*******************relevant blocks************************')
    print('prologue: %#x' % start)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    print('pre_dispatcher: %#x' % pre_dispatcher_node.addr)
    print('retn: %#x' % retn_node.addr)
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks:', [hex(addr) for addr in relevant_block_addrs])

    print('*******************symbolic execution*********************')
    relevants = relevant_nodes
    relevants.append(prologue_node)
    relevants_without_retn = copy.deepcopy(relevants)
    relevants.append(retn_node)
    relevant_block_addrs.extend([prologue_node.addr, retn_node.addr])

    flow = defaultdict(list)
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block: angr.block.Block = project.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addrs = set([])
        # insnsblock.capstone.insns
        insns: List[angr.block.CapstoneInsn] = block.capstone.insns
        # 遍历所有真实块中的所有指令
        for ins in insns:
            if project.arch.name in ARCH_X86:
                if ins.insn.mnemonic.startswith('cmov'):# 发现cmov 就加入要patch的指令
                    # only record the first one
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic.startswith('call'): # 发现call 加入hook
                    hook_addrs.add(ins.insn.address)
            # 以下不需要关注
            elif project.arch.name in ARCH_ARM:
                if ins.insn.mnemonic != 'mov' and ins.insn.mnemonic.startswith('mov'):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blx'}:
                    hook_addrs.add(ins.insn.address)
            elif project.arch.name in ARCH_ARM64:
                if ins.insn.mnemonic.startswith('cset'):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blr'}:
                    hook_addrs.add(ins.insn.address)

        if has_branches:
            # 分别执行两个分支语句 返回的应该是到的真实块地址
            tmp_addr = symbolic_execution(
                project, 
                relevant_block_addrs,
                relevant.addr, 
                hook_addrs, 
                claripy.BVV(1, 1),  # 设置ITE的cond为1
                True
            )
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr) # flow[relevant]代表一个真实块下一个所能到达的真实块

            tmp_addr = symbolic_execution(
                project, 
                relevant_block_addrs,
                relevant.addr, 
                hook_addrs, 
                claripy.BVV(0, 1), # 设置ITE的cond为0
                True
            )
            
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)
        else:
            tmp_addr = symbolic_execution(
                project, 
                relevant_block_addrs,
                relevant.addr,
                hook_addrs
            )
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)

    print('************************flow******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    print('%#x: ' % retn_node.addr, [])

    print('************************patch*****************************')
    with open(filename, 'rb') as origin:
        # Attention: can't transform to str by calling decode() directly. so use bytearray instead.
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    recovery_file = filename + '_recovered'
    recovery = open(recovery_file, 'wb')

    # patch irrelevant blocks
    for nop_node in nop_nodes:
        # nop_node.addr-base_addr 为start_addr 以文件偏移为基址的
        fill_nop(origin_data, nop_node.addr-base_addr,
                 nop_node.size, project.arch)

    # remove unnecessary control flows
    # parent 就是这个真实块 childs 就是下个真实块的集合
    for parent, childs in flow.items():
        if len(childs) == 1:# 最后一条指令替换成jmp 
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
            file_offset = last_instr.address - base_addr
            # patch the last instruction to jmp
            if project.arch.name in ARCH_X86:
                # 清零最后一条指令 大概size是5
                fill_nop(origin_data, file_offset,
                         last_instr.size, project.arch)
                patch_value = ins_j_jmp_hex_x86(last_instr.address, childs[0], 'jmp')
            elif project.arch.name in ARCH_ARM:
                patch_value = ins_b_jmp_hex_arm(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            elif project.arch.name in ARCH_ARM64:
                # FIXME: For aarch64/arm64, the last instruction of prologue seems useful in some cases, so patch the next instruction instead.
                if parent.addr == start:
                    file_offset += 4
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address+4, childs[0], 'b')
                else:
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            patch_instruction(origin_data, file_offset, patch_value)
        else:# 从这个真实块出去能到达多个真实块 那么这个基本块就是负责控制分支的 而不参与具体的运算
            pdb.set_trace()
            instr = patch_instrs[parent] # 前面加入的cmov指令
            file_offset = instr.address - base_addr
            # patch instructions starting from `cmovx` to the end of block
            '''
            40086a:       b8 39 b0 59 af          mov    eax,0xaf59b039
            40086f:       b9 36 12 bb 0c          mov    ecx,0xcbb1236
            400874:       81 7d e8 a1 01 00 00    cmp    DWORD PTR [rbp-0x18],0x1a1
            40087b:       0f 44 c1                cmove  eax,ecx
            40087e:       89 45 e4                mov    DWORD PTR [rbp-0x1c],eax
            400881:       e9 15 01 00 00          jmp    40099b <check_password+0x46b>
            400886:       b8 39 b0 59 af          mov    eax,0xaf59b039

            ---------------------------------------- 
            | mov    eax,0xaf59b039                | <<- parent.addr  ---------------|
            | mov    ecx,0xcbb1236                 |                                 |
            | cmp    DWORD PTR [rbp-0x18],0x1a1    |                             parent.size
   block    | cmove  eax,ecx                       | <<- instr.address --------------|-----------| 
            | mov    DWORD PTR [rbp-0x1c],eax      |                                 |           |
            | jmp    40099b <check_password+0x46b> |                                 |        length
            |--------------------------------------|---------------------------------|-----------|
            '''
            assert instr.address >= parent.addr
            fill_nop(
                origin_data, 
                file_offset, 
                (parent.addr + parent.size) - instr.address, 
                project.arch
            )
            if project.arch.name in ARCH_X86:
                # patch the cmovx instruction to jx instruction
                # 原先这个指令是cmove的话 就改成je 然后下面的就直接jmp就行 两个分支
                patch_value = ins_j_jmp_hex_x86(instr.address, childs[0], instr.mnemonic[len('cmov'):])
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 6 # 条件跳转字节码是6
                # patch the next instruction to jmp instrcution
                patch_value = ins_j_jmp_hex_x86(instr.address + 6, childs[1], 'jmp')
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM:
                # patch the movx instruction to bx instruction
                bx_cond = 'b' + instr.mnemonic[len('mov'):]
                patch_value = ins_b_jmp_hex_arm(instr.address, childs[0], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instrcution
                patch_value = ins_b_jmp_hex_arm(instr.address+4, childs[1], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)
            elif project.arch.name in ARCH_ARM64:
                # patch the cset.xx instruction to bx instruction
                bx_cond = instr.op_str.split(',')[-1].strip()
                patch_value = ins_b_jmp_hex_arm64(instr.address, childs[0], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                # patch the next instruction to b instruction
                patch_value = ins_b_jmp_hex_arm64(instr.address+4, childs[1], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == '__main__':
    main()
