LOCAL_HOSTS = {"", "localhost"}


def jobs_conflict(script_a, stored_a, script_b, stored_b):
    """True if two jobs share a host; jobs without real hosts only conflict with the same script or playbook."""

    hosts_a = set((stored_a or "").split("\n")) - LOCAL_HOSTS
    hosts_b = set((stored_b or "").split("\n")) - LOCAL_HOSTS
    if hosts_a & hosts_b:
        return True
    return script_a == script_b and not hosts_a and not hosts_b
