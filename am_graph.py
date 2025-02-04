
from pprint import pprint
from loguru import logger
import pdb
import itertools
from collections import defaultdict

import networkx

from angr.knowledge_plugins import Function


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args, fillvalue=fillvalue)


def to_supergraph(transition_graph: networkx.DiGraph):
    """
    Convert transition graph of a function to a super transition graph. A super transition graph is a graph that looks
    like IDA Pro's CFG, where calls to returning functions do not terminate basic blocks.

    :param networkx.DiGraph transition_graph: The transition graph.
    :return: A converted super transition graph
    :rtype networkx.DiGraph
    """

    # make a copy of the graph
    transition_graph = networkx.DiGraph(transition_graph)

    # remove all edges that transitions to outside
    for src, dst, data in list(transition_graph.edges(data=True)):
        # pprint(data)
        # {'ins_addr': 4195661, 'outside': False, 'stmt_idx': None, 'type': 'transition'}
        # ref: https://github.com/angr/angr/blob/36052256cc10f580005f8ca189c27d35ec5044ca/angr/knowledge_plugins/functions/function.py#L1411
        # transition边就是 正常基本块之间的转换 异常边应该是系统调用或者异常之类的状态转换
        # "outside transition edge"（外部转移边）是指从当前二进制程序的基本块转移到其他函数或者代码模块的转移边 这里全去除
        if data['type'] in ('transition', 'exception') and data.get('outside', False) is True:
            transition_graph.remove_edge(src, dst)
        # 这里存在原作者一个逻辑错误 一个图的所有边 怎么可能存在一个边的入度为0呢？
        # assert  transition_graph.in_degree(dst) != 0
        # if transition_graph.in_degree(dst) == 0: # 入度为0 这是一条多余的边
            # transition_graph.remove_node(dst)

    edges_to_shrink = set()

    # Find all edges to remove in the super graph
    for src in transition_graph.nodes():
        dsts = transition_graph[src]

        # there are two types of edges we want to remove:
        # - call or fake-rets, since we do not want blocks to break at calls
        # - boring jumps that directly transfer the control to the block immediately after the current block.(就是非条件跳转) this is
        #   usually caused by how VEX(angr用的ir分析器) breaks down basic blocks, which happens very often in MIPS

        # fake_return is an edge from a block that ends with a function call to the return site of the call
        # as opposed to a real return edge that comes from the called function
        # and it is generated in cfg analysis (cfgfast)

        
        # 这里的edges是一个Mapping, edges.keys()就是所有的src
        # edges: AtlasView({<BlockNode at 0x400554 (size 23)>: {'type': 'transition', 'outside': False, 'ins_addr': 4195661, 'stmt_idx': None}})
        # 只有一条边 且这个边的src的地址加上src基本块的大小正好是dst的地址 就是上文的boring jumps
        '''
        |-----------------| <- src.addr
        |                 |    src.size
        |-----------------|------------ <<- dst.addr
        |                 |
        |                 |
        '''
        if len(dsts) == 1 and src.addr + src.size == next(iter(dsts.keys())).addr:
            dst = next(iter(dsts.keys()))
            dst_in_edges = transition_graph.in_edges(dst)
            # pdb.set_trace()
            if len(dst_in_edges) == 1:# 只有一个入边 代表着两个基本块挨在一起 且直接跳转过来
                edges_to_shrink.add((src, dst))
                continue
        '''
        _FUNCTION_EDGETYPES = {
            None: Edge.UnknownJumpkind,
            "transition": Edge.Boring,
            "call": Edge.Call,
            "return": Edge.Return,
            "fake_return": Edge.FakeReturn,
            "syscall": Edge.Syscall,
            "exception": Edge.Exception,
        }
        '''
        # A fake_ret edge is an edge between call site and (the supposedly) return target.
        # fake_ret 应该就是call到下一个基本块之间的边 类似于如下
        '''
          400965:       e8 a6 fa ff ff          call   400410 <puts@plt>
          ----------------------------------------------------------------------- fake ret edge
          40096a:       c7 45 e4 1e e3 f7 cd    mov    DWORD PTR [rbp-0x1c],0xcdf7e31e
          400971:       89 85 64 ff ff ff       mov    DWORD PTR [rbp-0x9c],eax
          400977:       e9 1f 00 00 00          jmp    40099b <check_password+0x46b>
          40097c:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
          400983:       c7 45 e4 2b 15 ee e9    mov    DWORD PTR [rbp-0x1c],0xe9ee152b
          40098a:       e9 0c 00 00 00          jmp    40099b <check_password+0x46b>
          40098f:       8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
        '''
        if any(iter('type' in data and data['type'] not in ('fake_return', 'call') for data in dsts.values())):
            continue
        
        # shrink掉call的边
        for dst, data in dsts.items():
            if isinstance(dst, Function):
                continue
            if 'type' in data and data['type'] == 'fake_return':
                # 我严重怀疑没有return_from_call这个类型...... 还真没有
                if all(iter('type' in data and data['type'] is 'fake_return'
                            for _, _, data in transition_graph.in_edges(dst, data=True))):
                    edges_to_shrink.add((src, dst))
                break

    # Create the super graph
    super_graph = networkx.DiGraph()

    supernodes_map = {}

    function_nodes = set()  # it will be traversed after all other nodes are added into the supergraph

    for node in transition_graph.nodes():

        if isinstance(node, Function):
            function_nodes.add(node)
            # don't put functions into the supergraph
            continue

        dests_and_data = transition_graph[node]

        # make a super node
        if node in supernodes_map:
            src_supernode = supernodes_map[node]
        else:
            src_supernode = SuperCFGNode.from_cfgnode(node)
            supernodes_map[node] = src_supernode
            # insert it into the graph
            super_graph.add_node(src_supernode)

        if not dests_and_data:
            # might be an isolated node
            continue

        # Take src_supernode off the graph since we might modify it
        if src_supernode in super_graph:
            existing_in_edges = list(super_graph.in_edges(src_supernode, data=True))
            existing_out_edges = list(super_graph.out_edges(src_supernode, data=True))
            super_graph.remove_node(src_supernode)
        else:
            existing_in_edges = [ ]
            existing_out_edges = [ ]

        for dst, data in dests_and_data.items():

            edge = (node, dst)

            if edge in edges_to_shrink:

                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = None

                src_supernode.insert_cfgnode(dst)

                # update supernodes map
                supernodes_map[dst] = src_supernode

                # merge the other supernode
                if dst_supernode is not None:
                    src_supernode.merge(dst_supernode)

                    for src in dst_supernode.cfg_nodes:
                        supernodes_map[src] = src_supernode

                    # link all out edges of dst_supernode to src_supernode
                    for dst_, data_ in super_graph[dst_supernode].items():
                        super_graph.add_edge(src_supernode, dst_, **data_)

                    # link all in edges of dst_supernode to src_supernode
                    for src_, _, data_ in super_graph.in_edges(dst_supernode, data=True):
                        super_graph.add_edge(src_, src_supernode, **data_)

                        if 'type' in data_ and data_['type'] in ('transition', 'exception'):
                            if not ('ins_addr' in data_ and 'stmt_idx' in data_):
                                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                                # stmt_idx weren't properly set onto edges
                                continue
                            src_supernode.register_out_branch(data_['ins_addr'], data_['stmt_idx'], data_['type'],
                                                              dst_supernode.addr
                                                              )

                    super_graph.remove_node(dst_supernode)

            else:
                if isinstance(dst, Function):
                    # skip all functions
                    continue

                # make a super node
                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = SuperCFGNode.from_cfgnode(dst)
                    supernodes_map[dst] = dst_supernode

                super_graph.add_edge(src_supernode, dst_supernode, **data)

                if 'type' in data and data['type'] in ('transition', 'exception'):
                    if not ('ins_addr' in data and 'stmt_idx' in data):
                        # this is a hack to work around the issue in Function.normalize() where ins_addr and
                        # stmt_idx weren't properly set onto edges
                        continue
                    src_supernode.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'],
                                                      dst_supernode.addr
                                                      )

        # add back the node (in case there are no edges)
        super_graph.add_node(src_supernode)
        # add back the old edges
        for src, _, data in existing_in_edges:
            super_graph.add_edge(src, src_supernode, **data)
        for _, dst, data in existing_out_edges:
            super_graph.add_edge(src_supernode, dst, **data)

    for node in function_nodes:
        in_edges = transition_graph.in_edges(node, data=True)

        for src, _, data in in_edges:
            if not ('ins_addr' in data and 'stmt_idx' in data):
                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                # stmt_idx weren't properly set onto edges
                continue
            supernode = supernodes_map[src]
            supernode.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'], node.addr)

    return super_graph


class OutBranch:
    def __init__(self, ins_addr, stmt_idx, branch_type):
        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx
        self.type = branch_type

        self.targets = set()

    def __repr__(self):
        if self.ins_addr is None:
            return "<OutBranch at None, type %s>" % self.type
        return "<OutBranch at %#x, type %s>" % (self.ins_addr, self.type)

    def add_target(self, addr):
        self.targets.add(addr)

    def merge(self, other):
        """
        Merge with the other OutBranch descriptor.

        :param OutBranch other: The other item to merge with.
        :return: None
        """

        assert self.ins_addr == other.ins_addr
        assert self.type == other.type

        o = self.copy()
        o.targets |= other.targets

        return o

    def copy(self):
        o = OutBranch(self.ins_addr, self.stmt_idx, self.type)
        o.targets = self.targets.copy()
        return o

    def __eq__(self, other):
        if not isinstance(other, OutBranch):
            return False

        return self.ins_addr == other.ins_addr and \
               self.stmt_idx == other.stmt_idx and \
               self.type == other.type and \
               self.targets == other.targets

    def __hash__(self):
        return hash((self.ins_addr, self.stmt_idx, self.type))


class SuperCFGNode:
    def __init__(self, addr):
        self.addr = addr

        self.cfg_nodes = [ ]

        self.out_branches = defaultdict(dict)

    @property
    def size(self):
        return sum(node.size for node in self.cfg_nodes)

    @classmethod
    def from_cfgnode(cls, cfg_node):
        s = cls(cfg_node.addr)

        s.cfg_nodes.append(cfg_node)

        return s

    def insert_cfgnode(self, cfg_node):
        # TODO: Make it binary search/insertion
        for i, n in enumerate(self.cfg_nodes):
            if cfg_node.addr < n.addr:
                # insert before n
                self.cfg_nodes.insert(i, cfg_node)
                break
            elif cfg_node.addr == n.addr:
                break
        else:
            self.cfg_nodes.append(cfg_node)

        # update addr
        self.addr = self.cfg_nodes[0].addr

    def register_out_branch(self, ins_addr, stmt_idx, branch_type, target_addr):
        if ins_addr not in self.out_branches or stmt_idx not in self.out_branches[ins_addr]:
            self.out_branches[ins_addr][stmt_idx] = OutBranch(ins_addr, stmt_idx, branch_type)

        self.out_branches[ins_addr][stmt_idx].add_target(target_addr)

    def merge(self, other):
        """
        Merge another supernode into the current one.

        :param SuperCFGNode other: The supernode to merge with.
        :return: None
        """

        for n in other.cfg_nodes:
            self.insert_cfgnode(n)

        for ins_addr, outs in other.out_branches.items():
            if ins_addr in self.out_branches:
                for stmt_idx, item in outs.items():
                    if stmt_idx in self.out_branches[ins_addr]:
                        self.out_branches[ins_addr][stmt_idx].merge(item)
                    else:
                        self.out_branches[ins_addr][stmt_idx] = item

            else:
                item = next(iter(outs.values()))
                self.out_branches[ins_addr][item.stmt_idx] = item

    def __repr__(self):
        return "<SuperCFGNode %#08x, %d blocks, %d out branches>" % (self.addr, len(self.cfg_nodes),
                                                                     len(self.out_branches)
                                                                     )

    def __hash__(self):
        return hash(('supercfgnode', self.addr))

    def __eq__(self, other):
        if not isinstance(other, SuperCFGNode):
            return False

        return self.addr == other.addr
