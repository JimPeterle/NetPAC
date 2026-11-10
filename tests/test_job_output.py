from job_output import JobOutput


def test_small_output_is_kept():
    output = JobOutput(limit=100)
    output.add("hello ")
    output.add("world")
    assert output.take_live() == "hello world"
    assert output.take_live() == ""
    assert output.text() == "hello world"
    assert not output.truncated


def test_large_output_keeps_beginning_and_end():
    output = JobOutput(limit=20)
    for i in range(10):
        output.add(f"line{i}\n")
    text = output.text()
    assert output.truncated
    assert text.startswith("line0\n")
    assert text.endswith("line9\n")
    assert "bytes of output omitted" in text
    assert "line4" not in text


def test_live_view_stops_after_limit():
    output = JobOutput(limit=20)
    for i in range(10):
        output.add(f"line{i}\n")
    live = output.take_live()
    assert "Output is larger than" in live
    assert "line9" not in live
