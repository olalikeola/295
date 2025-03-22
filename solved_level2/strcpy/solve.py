import angr
import claripy

def get_func_address(project, func_name):
    cfg = project.analyses.CFGFast(fail_fast=True)
    func = cfg.kb.functions.get(func_name)
    return func.addr if func else None

def check(state, strcpy_addr):
    if state.ip.args[0] != strcpy_addr:
        return False
    
    source_buf = state.memory.load(state.regs.rsi, 8)
    source_buf_value = state.solver.eval(source_buf, cast_to=bytes)
    return b"HAHAHAHA" in source_buf_value

def main():
    binary = "strcpy_test"
    project = angr.Project(binary, auto_load_libs=False)
    
    strcpy_addr = get_func_address(project, "strcpy")
    if not strcpy_addr:
        return "Error: strcpy function not found."
    
    argv1 = claripy.BVS("argv1", 8 * 32)
    entry_state = project.factory.entry_state(args=[binary, argv1, "HAHAHAHA"])
    sm = project.factory.simgr(entry_state)
    
    sm.explore(find=lambda s: check(s, strcpy_addr))
    
    if sm.found:
        found_state = sm.found[0]
        password = found_state.solver.eval(argv1, cast_to=bytes)
        try:
            password = password[:password.index(b'\x00')]
        except ValueError:
            pass
        return password
    else:
        return "Couldn't find a valid password."

if __name__ == "__main__":
    password = main()
    if isinstance(password, bytes):
        print(f'The password is "{password.decode()}"')
    else:
        print(password)

