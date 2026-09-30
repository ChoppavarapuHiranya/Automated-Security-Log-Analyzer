import re


def parse_log_line(line):
    pattern = (
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
        r"(?P<event>Failed password|Accepted password)"
        r" for (?P<username>\S+)"
        r" from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        r" port (?P<port>\d+)"
    )

    match = re.search(pattern, line)

    if match:
        return match.groupdict()

    return None