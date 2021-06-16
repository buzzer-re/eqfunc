#!/usr/bin/python3
import r2pipe
import sys, json
import networkx as nx

INSIDE_NO_FILE = 1
OUTSIDE = 2

class R2_Graph:
    '''
    Open, analyze the code and then create a real generic graph represetation of a function data block graph
    by use networkx library, then perform graph analysis like isomorphism, which detect structured equally graphs
    '''
    def __init__(self, bin_path, target_function, r2 = None):
        '''
        R2_Graph constructor, open an radare2 session if possible
        :bin_path binary path if is not running inside R2
        :target_function to create a graph from
        :r2 instance if is running already inside 
        '''
        self.path = bin_path
        self.target_function = target_function
        if r2 is None:
            self.r2 = r2pipe.open(bin_path, ["-e bin.cache=true"])                    
            if not self.r2:
                raise Exception(f"Unable to open {bin_path}")
        else:
            self.r2 = r2

        self.base_graph = None
        self.matchs = 0

    def get_r2(self):
        '''
        Get R2 instance

        '''
        return self.r2

    def analyze(self):
        '''
        Analyze everything, and auto rename, then create a graph to the target function
        '''
        self.r2.cmd('aaa')        
        self.base_graph = self.create_graph(self.target_function, True)

    def create_graph(self, target_function, is_base=False):
        '''
        Create a graph from a block function graph by mapping all the jumps 
        and fails to known node numbers and connecting the edges

        :target_function a function to be transnformed into a graph
        :is_base: If is the base graph, raise an exception if something goes wrong
        '''
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
    
    def is_equal(self, cmp_graph, rename=None, fn_address=0):
        '''
        Check if a given graph is isomorph, rename if needed
        :cmp_grap Graph to compare
        :rename new name, it will be append to 'similar_'
        :fn_address function address to rename
        '''
        if nx.is_isomorphic(self.base_graph, cmp_graph):
            if rename and fn_address != 0:
                self.matchs += 1
                new_name = f'similar_{rename}_{self.matchs}'
                self.r2.cmd(f'afn {new_name} @ {fn_address}; s-')
            
            return True


def is_inside():
    '''
    Check if is already inside the shell by checking the filename
    '''
    r2 = r2pipe.open()
    try:
        filename = r2.cmd('o.')
        if 'malloc' in filename: # Open without file            
            return INSIDE_NO_FILE

        return r2
    except:
        return OUTSIDE # Not inside

def main(args, r2_instance = None):
    '''
    Create and check function isomorphism using function graph

    :args with the name of the target and function address
    :r2_instance if already inside r2/rizin
    '''
    bin_path = None
    target_func = None
    new_name = None
    r2 = None
    
    if r2_instance:
        target_func, new_name = args
        r2 = r2_instance
    else:
        bin_path, target_func = args
    
    r2_graph = R2_Graph(bin_path, target_func, r2_instance)
    r2_graph.analyze()

    if r2_instance is None:
        r2 = r2_graph.get_r2()

    func_address = int(r2.cmd(f's {target_func};s'), base=16)

    # List all known functions
    fcnl = [x['offset'] for x in json.loads(r2.cmd('aflj')) if x['offset'] != func_address]
    
    for fcn in fcnl:
        g = r2_graph.create_graph(target_function=fcn)
        if r2_graph.is_equal(g, rename=new_name, fn_address=fcn):
            print(f"Function {hex(fcn)} has the same function structure!")
    


if __name__ == '__main__':
    arg_l = 3
    help_msg = ""
    display_help = False
    r2 = is_inside()
    display_help = r2 == INSIDE_NO_FILE or r2 == OUTSIDE

    if display_help:
        help_msg = f"{sys.argv[0]} binary_path function_address"
    else:
        help_msg = "#!pipe python r2_similarfunc.py address newname"

    if len(sys.argv) < arg_l or display_help:
        print(help_msg)
        sys.exit(1)

    main([sys.argv[1], sys.argv[2]], r2)
