import sys

def eprint(*argss, **kwargs):
    print(*argss, file=sys.stderr, **kwargs)
