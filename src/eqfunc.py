#!/usr/bin/python3
import sys

import graph


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
    
    r2_graph = graph.Graph(bin_path, target_func, pipe_instance)
    if not r2_graph.analyze():
        print("Invalid binary or function address")
        sys.exit(1)

    if pipe_instance is None:
        r2 = r2_graph.get_r2()

    func_address = int(r2.cmd(f's {target_func};s'), base=16)

    # List all known functions
    fcnl = [x['offset'] for x in r2.cmdj('aflj') if x['offset'] != func_address]

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
    pipe = None
    if graph.inside_rz or graph.inside_r2:
        pipe = graph.pipe.open()

    if pipe:
        help_msg = f"#!pipe python {sys.argv[0]}.py address newname"
    else:
        help_msg = f"{sys.argv[0]} binary_path function_address"

    if len(sys.argv) < arg_l:
        print(help_msg)
        sys.exit(1)

    main([sys.argv[1], sys.argv[2]], pipe)
