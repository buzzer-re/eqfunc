#!/usr/bin/python3
import argparse
import os, sys
from subprocess import call
from networkx.classes import graph
import yaml

# Graph import in if __name__ block


def internal_similars(bin_graph: graph.Graph, base_addres) -> list:
    # Internal functions list
    pipe = bin_graph.get_pipe()
    fcnl = [x['offset'] for x in pipe.cmdj('aflj') if x['offset'] != base_addres]

    similars = []
    for fcn in fcnl:
        g = bin_graph.create_graph(target_function=fcn)
        if not g:
            continue

        if bin_graph.is_equal(g, rename='', fn_address=fcn):
            similars.append(hex(fcn))
    
    return similars
    

def external_similars(bin_graph: graph.Graph, compare_graph: graph.Graph) -> dict:
    exPipe = compare_graph.get_pipe()
    primary_file = bin_graph.get_name()
    compare_name = compare_graph.get_name()
    fcnl = [x['offset'] for x in exPipe.cmdj('aflj') if x['offset']]

    similars = {
        "len": 0,
        primary_file: {
            compare_name: []
        }
    }

    for fcn in fcnl:
        # Get networkx graph object
        g = compare_graph.create_graph(target_function=fcn)
        if bin_graph.is_equal(g, rename='', fn_address=fcn):
            similars[primary_file][compare_name].append(hex(fcn))
            similars["len"] += 1

    return similars



def main(called_by_script=False, script_args=()):
    pipe_instance = None
    if not called_by_script:
        args = argparse.ArgumentParser(description="Discover structural equal function")
        args.add_argument("binary", help="Binary to be analyzed and used as base")
        args.add_argument("function", help="Function to be used as base")
        args.add_argument("--compare", help="An unique file to compare")
        args = args.parse_args()

        binary = args.binary
        function = args.function
        compare = args.compare
        if not os.path.exists(binary):
            print(f"Invalid base file {binary}")
            sys.exit(1)
    else:
        function, pipe_instance = script_args 
        compare = None


    if pipe_instance:
        binGraph = graph.Graph(None, function, pipe_instance)
    else:
        binGraph = graph.Graph(binary, function)

    if not binGraph.analyze(gen_graph=True):
        return None
    
    if compare: # Compare two binaries
        if not os.path.exists(compare):
            print(f"Invalid file {compare}")
            sys.exit(1)

        compareGraph = graph.Graph(compare, None)
        compareGraph.analyze()
        similars = external_similars(binGraph, compareGraph)


        if similars["len"] > 0:
            print(yaml.dump(similars))
        else:
            print("No similar function between the binaries")

    else: # Internal discovery
        similars = internal_similars(binGraph, function)
        
        if called_by_script:
            return similars

        if similars:
            print("Similars: ")
            print(yaml.dump(similars))
        else:
            print(f"No similar functions to {function}")

if __name__ == '__main__':
    import graph
    main()
else:
    # Import as module, used for scripting 
    from . import graph
