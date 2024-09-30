

def collect_action_info(found_state,start_address):
    addrs = []
    index = 0
    addr2action = {

    }
    for action in found_state.history.actions:
        real_addr = action.ins_addr - start_address

        if index != 0 and addrs[index - 1] == real_addr:
            addr2action[real_addr].append(action)
            continue
        addrs.append(real_addr)
        addr2action[real_addr] = []
        addr2action[real_addr].append(action)
        index += 1

    return addrs,addr2action