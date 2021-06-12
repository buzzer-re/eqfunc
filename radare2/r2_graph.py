import r2pipe
import sys, json
from pprint import pprint
import networkx as nx

class R2_Graph:
    def __init__(self, bin_path, target_function):
        self.path = bin_path
        self.target_function = target_function
        self.r2 = r2pipe.open(bin_path, ["-e bin.cache=true"])
        if not self.r2:
            raise Exception(f"Unable to open {bin_path}")
    
    def get_r2(self):
        return self.r2

    def analyze(self):
        self.r2.cmd('aaa')        
        self.base_graph = self.create_graph(self.target_function)

    def create_graph(self, target_function, is_base=False):
        tmp_graph = None
        graph = nx.Graph()
        mapping = {}
        try:
            tmp_graph = json.loads(self.r2.cmd(f's {target_function}; agfj'))
        except Exception as e:
            msg = f"Unable to generate a data block graph from {target_function}"
            if is_base:
                raise Exception(msg)
            print(msg)
            return

        for i, k in enumerate(tmp_graph[0]['blocks']):
            offset  = k['offset']
            mapping[offset]  = i
            graph.add_node(i)
        
        for k in tmp_graph[0]['blocks']:
            offset = k['offset']
            jmp = k.get('jump', None)
            fail = k.get('fail', None)

            if jmp and jmp in mapping:
                graph.add_edge(mapping[offset], mapping[jmp])
            if fail and fail in mapping:
                graph.add_edge(mapping[offset], mapping[fail])

        return graph
    
    def is_equal(self, cmp_graph, rename=False, name='', base_graph=None, r2_instance=None, cmp_address=0):
        if not base_graph:
            base_graph = self.base_graph
        if not r2_instance:
            r2_instance = self.r2

        if nx.is_isomorphic(base_graph, cmp_graph):
            if rename and cmp_address != 0:
                new_name = f'similar_{name}'
                r2.cmd(f's {cmp_address}; afn {new_name}; s-')
            
            return True

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'./{sys.argv[0]} binary_path function_address')
        sys.exit(1)

    target_func = sys.argv[2]

    try:
        if '0x' in target_func:
            target_func = int(target_func, base=16)
        else:
            target_func = int(sys.argv[2])
    except:
        raise Exception(f"Invalid {target_func} number")

    bin_path = sys.argv[1]
    
    r2_graph = R2_Graph(bin_path, target_func)
    r2_graph.analyze()

    r2 = r2_graph.get_r2()

    fcnl = [x['offset'] for x in json.loads(r2.cmd('aflj')) if x['offset'] != target_func]

    for fcn in fcnl:
        g = r2_graph.create_graph(target_function=fcn)
        if r2_graph.is_equal(g):
            print(f"Function {hex(fcn)} has the same block graph structure!")


