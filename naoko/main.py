#!/usr/bin/env python
# The supervisor process that is responsible for starting and restarting Naoko
import os, sys, time
import signal
import threading
from multiprocessing import Pipe, Process
name = "Launcher"

from naoko import Naoko
from settings import *

# Don't fork too often
MIN_DUR = 2.5

kicked = False
restarting = False

# Set up logging
FORMAT = '%(asctime)s %(name)-15s:%(levelname)-8s - %(message)s'
DATEFMT = '%Y-%m-%d %H:%M:%S'
logging.basicConfig(format=FORMAT, datefmt=DATEFMT, stream=sys.__stderr__)
logger = logging.getLogger("socket.io client")
logger.setLevel(LOG_LEVEL)
(info, debug, warning, error) = (logger.info, logger.debug, logger.warning, logger.error)

class throttle:
    def __init__ (self, fn):
        self.fn = fn
        self.delay = MIN_DUR
        self.last_call = 0

    def __call__ (self, *args, **kwargs):
        if not restarting and time.time() - self.last_call < 60:
            self.delay *= 2
            self.delay = self.delay if self.delay < 60 * 10 else 60*10
        else:
            self.delay = MIN_DUR
        remaining = self.delay - time.time() + self.last_call
        if not kicked and remaining > 0:
            time.sleep(remaining)
        self.last_call = time.time()
        self.fn(*args, **kwargs)

def spawn(script):
    (pipe_in, pipe_out) = Pipe(False)
    p = Process(target=script, args=(kicked, pipe_out,))
    p.daemon = True # If the main process crashes for any reason then kill the child process
    p.start()
    pipe_out.close()
    return (pipe_in, p)

@throttle
def run(script):
    global child
    global kicked
    (child_pipe, child) = spawn (script)
    kicked = False
    restarting = False
    print "[%s] Forked off (%d)\n" % (name, child.pid)
    try:
        while child_pipe.poll(TIMEOUT):
            buf = child_pipe.recv()
            if buf == "RESTART":
                time.sleep(5)
                break
            elif buf == "HEALTHY":
                restarting = True
                continue
            elif buf == "KICKED":
                print "Kicked, attempting recovery"
                kicked = False
                break
            else:
                raise Exception("Received invalid message (%s)"% (buf))
    except EOFError:
        print "[%s] EOF on child pipe" % (name)
    except IOError:
        print "[%s] IOError on child pipe" % (name)
    except OSError as e:
        print "Received exception ", str(e)
    finally:
        child.terminate()

if __name__ == '__main__':
    try:
        while True:
            run(Naoko)
    except KeyboardInterrupt:
        print "\n Shutting Down"
