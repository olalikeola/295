import angr
import claripy

def solve_auth_bypass(binary_path):
    proj = angr.Project(binary_path)
    
    username = claripy.BVS('username', 8 * 8)  
    password = claripy.BVS('password', 8 * 8) 
    
    state = proj.factory.entry_state(
        args=['./auth'],
        stdin=username + password
    )
    

    pg = proj.factory.path_group(state)
  
    success_addr = 0x4012D0  # Address of accepted() function
    failure_addr = 0x4011E0  # Address of rejected() function
    

    pg.explore(
        find=success_addr,
        avoid=failure_addr
    )
    

    if len(pg.found) > 0:
        found_path = pg.found[0]
        
     
        input_data = found_path.state.posix.dumps(0).strip(b'\x00')
        
        
        username_input = input_data[:8]
        password_input = input_data[8:]
        
        print(f"Found authentication bypass!")
        print(f"Username: {username_input.decode('utf-8')}")
        print(f"Password: {password_input.decode('utf-8')}")
        
        return username_input, password_input
    else:
        print("No authentication bypass found")
        return None, None

# Usage
if __name__ == "__main__":
    binary_path = "./auth"
    username, password = solve_auth_bypass(binary_path)
