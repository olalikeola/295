import angr
import claripy

proj = angr.Project('./use_after_free', auto_load_libs=False)


state = proj.factory.entry_state()


simgr = proj.factory.simulation_manager(state)


simgr.explore()


if simgr.found:
    for found in simgr.found:
        print("Found a state that reached the use-after-free condition!")
        print(found)
else:
    print("No use-after-free condition found.")
