from . import eqfunc

def find_equals(addr, pipe_instance, using_rizin):
    eqfunc.graph.rizin = using_rizin
    eqfunc.graph.inside_rz = using_rizin
    args = (addr, pipe_instance)
    return eqfunc.main(called_by_script=True, script_args=args)

    pass