import angr

proj = angr.Project('./buffer_overflow', auto_load_libs=False)

state = proj.factory.entry_state()

simgr = proj.factory.simulation_manager(state)

simgr.explore()

if simgr.found:
    for found in simgr.found:
        print("Found a state that reached the buffer overflow condition!")
        print(found)
else:
    print("No buffer overflow condition found.")
