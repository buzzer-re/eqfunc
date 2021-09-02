import networkx as nx
import platform
import psutil
import os

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

class Graph:
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

    def get_pipe(self):
        '''
        Get R2/pipe instance

        '''
        return self.r2

    def get_name(self):
        return os.path.basename(self.path)

    def analyze(self, gen_graph=True) -> bool:
        '''
        Analyze everything, and auto rename, then create a graph to the target function
        '''
        self.r2.cmd('aaa')  
        if gen_graph:
            self.base_graph = self.create_graph(self.target_function, True)
            if not self.base_graph:
                return False
        return True

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
            tmp_graph = self.r2.cmdj(f's {target_function}; agfj')
        except Exception as e:
            msg = f"Unable to generate a data block graph from {target_function}"
            if is_base:
                raise Exception(msg)
            return

        if not tmp_graph and is_base:
            return None

        # Map all address to numbers between 0-numBlocks
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
