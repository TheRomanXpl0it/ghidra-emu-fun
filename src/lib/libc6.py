import hooks
import logging
import sys
import random


name = 'libc6'

logger = logging.getLogger(str(random.random()).replace(".","_"))
logger.setLevel(logging.INFO)

h_stdout = logging.StreamHandler(sys.stdout)
h_stdout.setLevel(logging.INFO)
logger.addHandler(h_stdout)

@hooks.args
def exit(code):
    logger.info('exit: code = {}'.format(code))
    assert(False)

@hooks.args
def puts(p):
    s = p.readCString()
    logger.info('puts: {}'.format(repr(s)))
    return 1

@hooks.args
def memcmp(mem1, mem2, size):
    for i in xrange(size):
        c1 = mem1[i]
        c2 = mem2[i]
        if c1 != c2:
            return 1 if c1 > c2 else -1
    return 0

@hooks.args
def strcmp(s1, s2):
    i = 0
    while True:
        c1 = s1[i]
        c2 = s2[i]
        if c1 != c2:
            return 1 if c1 > c2 else -1
        if c1 == 0:
            return 0
        i += 1

exports = [
    puts,
    exit,
    memcmp,
    strcmp
]
