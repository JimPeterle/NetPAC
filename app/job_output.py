import collections


MAX_JOB_OUTPUT_BYTES = 10 * 1024 * 1024


class JobOutput:
    """Collects job output up to MAX_JOB_OUTPUT_BYTES, keeping the beginning and the end."""

    def __init__(self, limit=MAX_JOB_OUTPUT_BYTES):
        """Starts with an empty buffer; half of the limit is used for the beginning, half for the end."""

        self.head_limit = limit // 2
        self.tail_limit = limit - self.head_limit
        self.head, self.head_size = [], 0
        self.tail, self.tail_size = collections.deque(), 0
        self.live, self.truncated, self.dropped = [], False, 0

    def add(self, text):
        """Adds a piece of output."""

        size = len(text.encode("utf-8", "replace"))
        if not self.truncated and self.head_size + size <= self.head_limit:
            self.head.append(text)
            self.head_size += size
            self.live.append(text)
            return
        if not self.truncated:
            self.truncated = True
            self.live.append(f"\n[NetPAC] Output is larger than {MAX_JOB_OUTPUT_BYTES // (1024 * 1024)} MB, "
                             "the end is shown when the job has finished.\n")
        self.tail.append((text, size))
        self.tail_size += size
        while self.tail_size > self.tail_limit and self.tail:
            old_text, old_size = self.tail.popleft()
            self.tail_size -= old_size
            self.dropped += old_size

    def take_live(self):
        """Returns the output not yet written to the live view."""

        text, self.live = "".join(self.live), []
        return text

    def text(self):
        """Returns the stored output (beginning, omission note, end)."""

        note = f"\n\n[NetPAC] ... {self.dropped} bytes of output omitted ...\n\n" if self.dropped else ""
        return "".join(self.head) + note + "".join(t for t, _ in self.tail)
