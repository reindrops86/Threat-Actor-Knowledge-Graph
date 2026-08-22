# Threat Actor Knowledge Graph Analysis

This notebook loads a small cyber attribution graph and queries relationships between actors, infrastructure, TTPs, and campaigns.

import sys
from pathlib import Path

project_root = Path.cwd().resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from threat_actor_graph import build_demo_graph

graph = build_demo_graph()
graph.graph.nodes(data=True)

actors = graph.list_nodes_by_type('actor')
for actor in actors:
    related = graph.find_related_nodes(actor)
    print(actor, '->', related)

import matplotlib.pyplot as plt
import networkx as nx

pos = nx.spring_layout(graph.graph, seed=42)
node_types = {'actor': '#ff7f0e', 'infrastructure': '#2ca02c', 'ttp': '#1f77b4', 'campaign': '#d62728'}
colors = [node_types.get(graph.graph.nodes[n].get('type'), '#7f7f7f') for n in graph.graph.nodes]

plt.figure(figsize=(12, 8))
nx.draw(graph.graph, pos, with_labels=True, node_color=colors, node_size=1500, edge_color='#555', arrows=True)
plt.title('Threat Actor Attribution Graph')
plt.tight_layout()
plt.show()

def explain_attribution(actor_name: str):
    path = graph.path_between(actor_name, 'Operation Ghost')
    if not path:
    path = graph.path_between(actor_name, 'Trident Finance')
    if not path:
    path = graph.path_between(actor_name, 'Moonlight Incursion')
    return path

for actor in actors:
    print(f'{actor}: {explain_attribution(actor)}')
