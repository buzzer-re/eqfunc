#!/usr/bin/python3
import sys, json
import platform
import networkx as nx
import psutil

# Chose the correct import, user can be runing that inside radare2,rizin or cutter
calle = psutil.Process(psutil.Process().ppid()).cmdline()[0]

if platform.system() == 'Windows':
    calle = calle.split("\\")[-1]

rizin = False

inside_r2 = False
inside_rz = False
rznames = ['rizin', 'rizin.exe', 'cutter', 'cutter.exe']
r2names = ['r2', 'radare2', 'radare2.exe', 'r2.exe']
# Yep, that all the possible names to rizin, r2 and cutter

if calle in rznames:
    import rzpipe as pipe
    inside_rz = True
    rizin = True
elif calle in r2names:
    import r2pipe as pipe 
    inside_r2 = True
else:
    try:
        import r2pipe as pipe
    except:
        try:
            import rzpipe as pipe
            rizin = True

        except Exception as e:
            raise e
#end choose import

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
            self.r2 = pipe.open(bin_path, ["-e bin.cache=true" if not rizin else "-e io.cache=true"])                    
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
        return self.base_graph

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

        if not tmp_graph and is_base:
            return None

        # Map all address to numbers between 0-nuBlocks
        # because the node number can't be unique 
        for i, k in enumerate(tmp_graph[0]['blocks']):
            offset  = k['offset']
            mapping[offset]  = i
            graph.add_node(i)
        
        # Now connect each node in each block connection in the function graph
        for k in tmp_graph[0]['blocks']:
            offset = k['offset']
            jmp = k.get('jump', None)
            fail = k.get('fail', None)

            if jmp in mapping:
                graph.add_edge(mapping[offset], mapping[jmp])
            if fail in mapping:
                graph.add_edge(mapping[offset], mapping[fail])

        return graph
    
    def is_equal(self, cmp_graph, rename=None, fn_address=0):
        '''
        Check if a given graph is isomorph and rename if asked to
        :cmp_grap Graph to compare
        :rename new name, it will be formated as 'similar_{new_name}_{id}'
        :fn_address function address to rename
        '''
        if nx.is_isomorphic(self.base_graph, cmp_graph):
            if rename and fn_address != 0:
                self.matchs += 1
                new_name = f'similar_{rename}_{self.matchs}'
                self.r2.cmd(f'afn {new_name} @ {fn_address}')
            
            return True


def main(args, pipe_instance = None, return_only = False):
    '''
    Create and check function isomorphism using function graph

    :args with the name of the target and function address
    :pipe_instance if already inside r2/rizin
    '''
    bin_path = None
    target_func = None
    new_name = None
    r2 = None
    
    if pipe_instance:
        target_func, new_name = args
        r2 = pipe_instance
    else:
        bin_path, target_func = args
    
    r2_graph = R2_Graph(bin_path, target_func, pipe_instance)
    if not r2_graph.analyze():
        print("Invalid binary or function address")
        sys.exit(1)

    if pipe_instance is None:
        r2 = r2_graph.get_r2()

    func_address = int(r2.cmd(f's {target_func};s'), base=16)

    # List all known functions
    fcnl = [x['offset'] for x in json.loads(r2.cmd('aflj')) if x['offset'] != func_address]

    similars = []
    for fcn in fcnl:
        g = r2_graph.create_graph(target_function=fcn)
        if r2_graph.is_equal(g, rename=new_name, fn_address=fcn):
            similars.append(hex(fcn))
    
    r2.cmd(f's {func_address}')
    
    if return_only:
        return similars

    print(f"Found {len(similars)} functions with the same structure as {target_func}: ")
    if similars:
        for f in similars:
            print(f"\t- {f}")


def find_equals(addr, pipe_instance, is_rizin):
    '''
    Function to be used for scripting
    :addr to find similars
    :pipe_instance r2pipe or rzpipe isntance
    :is_rizin boolean to indicate if is using rizin
    '''
    rizin = is_rizin
    inside_rz = is_rizin
    args = (addr, None)
    return main(args, pipe_instance, return_only=True)



if __name__ == '__main__':
    arg_l = 3
    help_msg = ""
    r2 = None
    if inside_rz or inside_r2:
        r2 = pipe.open()

    if r2:
        help_msg = f"#!pipe python {sys.argv[0]}.py address newname"
    else:
        help_msg = f"{sys.argv[0]} binary_path function_address"

    if len(sys.argv) < arg_l:
        print(help_msg)
        sys.exit(1)

    main([sys.argv[1], sys.argv[2]], r2)
