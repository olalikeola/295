import angr
import claripy
import time

def solve_timing_challenge():
   
    p = angr.Project('timing_challenge', auto_load_libs=False)
    
    
    state = p.factory.entry_state()
    
    
    input_size = 20  # MAX_PASS from the C code
    input_sym = claripy.BVS('input', input_size * 8)
    
    
    for i in range(input_size):
        byte = claripy.Extract(i*8 + 7, i*8, input_sym)
        state.solver.add(byte >= claripy.BVV(ord(' '), 8))
        state.solver.add(byte <= claripy.BVV(ord('~'), 8))
    
    
    state.solver.add(claripy.Extract(8*19 + 7, 8*19, input_sym) == claripy.BVV(0, 8))
    
   
    sm = p.factory.simulation_manager(state)
    
    
    success_addr = None
    for addr, func in p.kb.functions.items():
        if b'Access granted!' in func.binary:
            success_addr = addr
            break
    
 
    sm.explore(find=success_addr, n=100)
    
  
    if sm.found:
        solution_state = sm.found[0]
        solution = solution_state.solver.eval(input_sym, cast_to=bytes).decode()
        print(f"Found solution: {solution}")
    else:
        print("No solution found")

if __name__ == '__main__':
    start_time = time.time()
    solve_timing_challenge()
    print(f"\nTime taken: {time.time() - start_time:.2f} seconds")
