from pprint import pprint
import networkx as nx

# 假设有一个现有的有向图 H
H = nx.DiGraph()
# H.add_nodes_from([1, 2, 3], )
H.add_edge(1, 2, type="fuck")
H.add_edge(2, 3, type="you")
H.add_edge(2, 4, type="you")

# 创建 H 的拷贝 G
G = nx.DiGraph(H)
pprint(G.edges.data())
for src, dst, data in list(G.edges(data=True)):
    pprint(data['type'])

'''
OutEdgeDataView([(1, 2, {'type': 'fuck'}), (2, 3, {'type': 'you'})])
'fuck'
'you'

'''


pprint(G[2])

'''
AtlasView({3: {'type': 'you'}, 4: {'type': 'you'}})
'''