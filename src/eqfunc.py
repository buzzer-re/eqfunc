#!/usr/bin/python3
import argparse
import sys
from networkx.classes import graph
import yaml

import graph


def internal_similars(bin_graph: graph.Graph, base_addres) -> list:
    # Internal functions list
    pipe = bin_graph.get_pipe()
    fcnl = [x['offset'] for x in pipe.cmdj('aflj') if x['offset'] != base_addres]

    similars = []
    for fcn in fcnl:
        g = bin_graph.create_graph(target_function=fcn)
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


def find_equals(addr, pipe_instance, is_rizin):
    '''
    Function to be used for scripting
    :addr to find similars
    :pipe_instance r2pipe or rzpipe isntance
    :is_rizin boolean to indicate if is using rizin
    '''
    # rizin = is_rizin
    # inside_rz = is_rizin
    args = (addr, None)
    graph.inside_rz = is_rizin
    graph.rizin = is_rizin
    # return main(called_by_script=True, (args, pipe_instance, return_only=True))


def main(called_by_script=False):
    args = argparse.ArgumentParser(description="Discover strucutered equal function")
    args.add_argument("binary", help="Binary to be analyzed and used as base")
    args.add_argument("function", help="Function to be used as base")
    args.add_argument("--path", help="Path to cluster similar functions", default=None)
    args.add_argument("--compare", help="An unique file to compare")
    args = args.parse_args()

    binary = args.binary
    function = args.function
    cluster_path = args.path
    compare = args.compare

    binGraph = graph.Graph(binary, function)
    binGraph.analyze()

    if args.compare: # Compare two binaries
        compareGraph = graph.Graph(compare, None)
        compareGraph.analyze()
        similars = external_similars(binGraph, compareGraph)
        
        if similars["len"] > 0:
            print(yaml.dump(similars))
        else:
            print("No similar function between the binaries")

    elif not cluster_path:
        similars = internal_similars(binGraph, function)
        if similars:
            print("Similars: ")
            print(yaml.dump(similars))
        else:
            print(f"No similar functions to {function}")
    
        



if __name__ == '__main__':
    main()