from queue_rules import jobs_conflict


def test_different_groups_run_in_parallel():
    assert not jobs_conflict("update.yml", "r1\nr2", "update.yml", "s1\ns2")


def test_shared_host_waits():
    assert jobs_conflict("update.yml", "r1\nr2", "backup.yml", "r1\ns1")


def test_different_playbooks_on_localhost_run_in_parallel():
    assert not jobs_conflict("a.yml", "localhost", "b.yml", "localhost")


def test_same_playbook_on_localhost_waits():
    assert jobs_conflict("a.yml", "localhost", "a.yml", "localhost")


def test_same_script_without_target_waits():
    assert jobs_conflict("backup.py", "", "backup.py", None)


def test_local_job_and_host_job_run_in_parallel():
    assert not jobs_conflict("a.yml", "localhost", "a.yml", "r1")
