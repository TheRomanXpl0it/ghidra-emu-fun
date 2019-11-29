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
    s = []
    i = 0
    logger.debug('reading:`{}`'.format(i))
    while p[i] != '\x00' and i < 1000:
        s.append(p[i])
        i += 1
        logger.debug('reading:`{}`'.format(i))
    logger.info('puts: {}'.format(repr(''.join(s))))
    return 1

exports = [
    puts,
    exit,
]