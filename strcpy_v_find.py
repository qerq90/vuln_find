from functools import partial

import angr
import logging

# in hex = 400000 - standart offset of angr
ANGR_STARTING_OFFSET = 4194304

logging.getLogger().setLevel('CRITICAL')

def get_all_func_adressess(func_name, cfg):
    return [addr for addr, func in cfg.kb.functions.items() if func_name == func.name]

p = angr.Project(input("Set file name:\n"), auto_load_libs=False)


cfg = p.analyses.CFGFast()

all_strcpy_adressess = get_all_func_adressess("strcpy", cfg)

argv = [p.filename]
argv.append("A")

def check(state, all_strcpy_adressess, argv, already_tainted_functions):
    if (state.ip.args[0] in all_strcpy_adressess and state.callstack.call_site_addr not in already_tainted_functions):
        # convention says, that string to copy is pushed in rsi register, so we check that register for data    
        BV_strcpy_src = state.memory.load(state.regs.rsi, len(argv[1]))
        strcpy_src = state.solver.eval(BV_strcpy_src, cast_to=bytes)
        return True if argv[1].encode() == strcpy_src else False
    
    return False

state = p.factory.entry_state(args=argv)
sm = p.factory.simulation_manager(state)

check_with_args = partial(check, all_strcpy_adressess=all_strcpy_adressess, argv=argv, already_tainted_functions=[])
explored = sm.explore(find=check_with_args)

tainted_function_places = []

for state in explored.found:
    tainted_function_places.append(state.callstack.call_site_addr)

while len(explored.found) > 0:
    sm = p.factory.simulation_manager(state)
    check_with_args = partial(check, all_strcpy_adressess=all_strcpy_adressess, argv=argv, already_tainted_functions=tainted_function_places)
    explored = sm.explore(find=check_with_args)
    
    for state in explored.found:
        tainted_function_places.append(state.callstack.call_site_addr)

if len(tainted_function_places) > 0:
    print("Found tainted places in binary:")
    
    for i, addr in enumerate(tainted_function_places):
        print(f"{i+1}) addr:{hex(addr - ANGR_STARTING_OFFSET)}")
else:
    print("No tainted places found")