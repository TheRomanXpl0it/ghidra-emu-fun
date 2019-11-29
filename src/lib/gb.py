import hooks
import logging
import sys
import random


name = 'gb'

logger = logging.getLogger(str(random.random()).replace(".","_"))
logger.setLevel(logging.INFO)

h_stdout = logging.StreamHandler(sys.stdout)
h_stdout.setLevel(logging.INFO)
logger.addHandler(h_stdout)


@hooks.args
def printf(fd, p):
    '''printf on file descriptor, but will always write on console'''
    s = []
    i = 0
    while p[i] != '\x00' and i < 1000:
        s.append(p[i])
        i += 1
    logger.info('printf({}): {}'.format(fd, repr(''.join(s))))
    return 1

exports = [
    printf,
]