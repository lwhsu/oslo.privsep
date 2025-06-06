# Copyright 2015 Rackspace Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Privilege separation ("privsep") daemon.

To ease transition this supports 2 alternative methods of starting the
daemon, all resulting in a helper process running with elevated
privileges and open socket(s) to the original process:

1. Start via fork()

   Assumes process currently has all required privileges and is about
   to drop them (perhaps by setuid to an unprivileged user).  If the
   the initial environment is secure and `PrivContext.start(Method.FORK)`
   is called early in `main()`, then this is the most secure and
   simplest.  In particular, if the initial process is already running
   as non-root (but with sufficient capabilities, via eg suitable
   systemd service files), then no part needs to involve uid=0 or
   sudo.

2. Start via sudo/rootwrap

   This starts the privsep helper on first use via sudo and rootwrap,
   and communicates via a temporary Unix socket passed on the command
   line.  The communication channel is briefly exposed in the
   filesystem, but is protected with file permissions and connecting
   to it only grants access to the unprivileged process.  Requires a
   suitable entry in sudoers or rootwrap.conf filters.

The privsep daemon exits when the communication channel is closed,
(which usually occurs when the unprivileged process exits).

"""

from concurrent import futures
import enum
import errno
import fcntl
import grp
import logging as pylogging
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import traceback

import debtcollector
import eventlet
from eventlet import patcher
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
from oslo_utils import importutils

from oslo_privsep._i18n import _
from oslo_privsep import capabilities
from oslo_privsep import comm
from oslo_privsep import mac_framework # For MACDaemon
from oslo_privsep.priv_context import Method # For MACDaemon logic (potentially)

LOG = logging.getLogger(__name__)


EVENTLET_MODULES = ('os', 'select', 'socket', 'thread', 'time', 'MySQLdb',
                    'builtins', 'subprocess')
EVENTLET_LIBRARIES = []


def _null():
    return []


_MONKEY_PATCHED = False
for module in EVENTLET_MODULES:
    if eventlet.patcher.is_monkey_patched(module):
        _MONKEY_PATCHED = True
    if hasattr(patcher, '_green_%s_modules' % module):
        method = getattr(patcher, '_green_%s_modules' % module)
    elif hasattr(patcher, '_green_%s' % module):
        method = getattr(patcher, '_green_%s' % module)
    else:
        method = _null()
    EVENTLET_LIBRARIES.append((module, method))

if _MONKEY_PATCHED:
    debtcollector.deprecate(
        "Eventlet support is deprecated and will be removed")


@enum.unique
class StdioFd(enum.IntEnum):
    # NOTE(gus): We can't use sys.std*.fileno() here.  sys.std*
    # objects may be random file-like objects that may not match the
    # true system std* fds - and indeed may not even have a file
    # descriptor at all (eg: test fixtures that monkey patch
    # fixtures.StringStream onto sys.stdout).  Below we always want
    # the _real_ well-known 0,1,2 Unix fds during os.dup2
    # manipulation.
    STDIN = 0
    STDOUT = 1
    STDERR = 2


class FailedToDropPrivileges(Exception):
    pass


class ProtocolError(Exception):
    pass


def set_cloexec(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    if (flags & fcntl.FD_CLOEXEC) == 0:
        flags |= fcntl.FD_CLOEXEC
        fcntl.fcntl(fd, fcntl.F_SETFD, flags)


def setuid(user_id_or_name):
    try:
        new_uid = int(user_id_or_name)
    except (TypeError, ValueError):
        new_uid = pwd.getpwnam(user_id_or_name).pw_uid
    if new_uid != 0:
        try:
            os.setuid(new_uid)
        except OSError:
            msg = _('Failed to set uid %s') % new_uid
            LOG.critical(msg)
            raise FailedToDropPrivileges(msg)


def setgid(group_id_or_name):
    try:
        new_gid = int(group_id_or_name)
    except (TypeError, ValueError):
        new_gid = grp.getgrnam(group_id_or_name).gr_gid
    if new_gid != 0:
        try:
            os.setgid(new_gid)
        except OSError:
            msg = _('Failed to set gid %s') % new_gid
            LOG.critical(msg)
            raise FailedToDropPrivileges(msg)


class PrivsepLogHandler(pylogging.Handler):
    def __init__(self, channel, processName=None):
        super().__init__()
        self.channel = channel
        self.processName = processName

    def emit(self, record):
        # Vaguely based on pylogging.handlers.SocketHandler.makePickle

        if self.processName:
            record.processName = self.processName

        data = dict(record.__dict__)

        if record.exc_info:
            if not record.exc_text:
                fmt = self.formatter or pylogging.Formatter()
                data['exc_text'] = fmt.formatException(record.exc_info)
            data['exc_info'] = None  # drop traceback in favor of exc_text

        # serialise msg now so we can drop (potentially unserialisable) args
        data['msg'] = record.getMessage()
        data['args'] = ()

        self.channel.send((None, (comm.Message.LOG, data)))


class _ClientChannel(comm.ClientChannel):
    """Our protocol, layered on the basic primitives in comm.ClientChannel"""

    def __init__(self, sock, context):
        self.log = logging.getLogger(context.conf.logger_name) # Use context's configured logger name
        self.log_traceback = context.conf.log_daemon_traceback
        super().__init__(sock)
        # No ping exchange here, will be done after helper is up
        # self.exchange_ping()

    def exchange_ping(self):
        try:
            # exchange "ready" messages
            reply = self.send_recv((comm.Message.PING.value,))
            success = reply[0] == comm.Message.PONG
        except Exception as e:
            self.log.exception('Error while sending initial PING to privsep: '
                               '%s', e)
            success = False
        if not success:
            msg = _('Privsep daemon failed to start')
            self.log.critical(msg)
            raise FailedToDropPrivileges(msg)

    def remote_call(self, name, args, kwargs, timeout):
        result = self.send_recv((comm.Message.CALL.value, name, args, kwargs),
                                timeout)
        if result[0] == comm.Message.RET:
            # (RET, return value)
            return result[1]
        elif result[0] == comm.Message.ERR:
            # (ERR, exc_type, args)
            #
            # TODO(gus): see what can be done to preserve traceback
            # (without leaking local values)
            exc_type = importutils.import_class(result[1])
            if self.log_traceback:
                try:
                    msg = 'Privsep daemon traceback: {}'.format(result[3])
                    self.log.warning(msg)
                except IndexError:
                    pass
            raise exc_type(*result[2])
        else:
            raise ProtocolError(_('Unexpected response: %r') % result)

    def out_of_band(self, msg):
        if msg[0] == comm.Message.LOG:
            # (LOG, LogRecord __dict__)
            message = {encodeutils.safe_decode(k): v
                       for k, v in msg[1].items()}
            record = pylogging.makeLogRecord(message)
            if self.log.isEnabledFor(record.levelno):
                self.log.logger.handle(record)
        else:
            self.log.warning('Ignoring unexpected OOB message from privileged '
                             'process: %r', msg)


def fdopen(fd, *args, **kwargs):
    # NOTE(gus): We can't just use os.fdopen() here and allow the
    # regular (optional) monkey_patching to do its thing.  Turns out
    # that regular file objects (as returned by os.fdopen) on python2
    # are broken in lots of ways regarding blocking behaviour.  We
    # *need* the newer io.* objects on py2 (doesn't matter on py3,
    # since the old file code has been replaced with io.*)
    if eventlet.patcher.is_monkey_patched('socket'):
        return eventlet.greenio.GreenPipe(fd, *args, **kwargs)
    else:
        return open(fd, *args, **kwargs)


def _fd_logger(level=logging.WARN):
    """Helper that returns a file object that is asynchronously logged"""
    read_fd, write_fd = os.pipe()
    read_end = fdopen(read_fd, 'r', 1)
    write_end = fdopen(write_fd, 'w', 1)

    def logger(f):
        for line in f:
            LOG.log(level, 'privsep log: %s', line.rstrip())
    t = threading.Thread(
        name='fd_logger',
        target=logger, args=(read_end,)
    )
    t.daemon = True
    t.start()

    return write_end


def replace_logging(handler, log_root=None):
    if log_root is None:
        log_root = logging.getLogger(None).logger  # root logger
    for h in log_root.handlers:
        log_root.removeHandler(h)
    log_root.addHandler(handler)


def un_monkey_patch():
    for eventlet_mod_name, func_modules in EVENTLET_LIBRARIES:
        if not eventlet.patcher.is_monkey_patched(eventlet_mod_name):
            continue

        for name, mod in func_modules():
            patched_mod = sys.modules.get(name)
            orig_mod = eventlet.patcher.original(name)
            for attr_name in mod.__patched__:
                patched_attr = getattr(mod, attr_name, None)
                unpatched_attr = getattr(orig_mod, attr_name, None)
                if patched_attr is not None:
                    setattr(patched_mod, attr_name, unpatched_attr)


class ForkingClientChannel(_ClientChannel):
    def __init__(self, context):
        """Start privsep daemon using fork()

        Assumes we already have required privileges.
        """

        sock_a, sock_b = socket.socketpair()

        for s in (sock_a, sock_b):
            s.setblocking(True)
            # Important that these sockets don't get leaked
            set_cloexec(s)

        # Try to prevent any buffered output from being written by both
        # parent and child.
        for f in (sys.stdout, sys.stderr):
            f.flush()

        if os.fork() == 0:
            # child
            un_monkey_patch()

            channel = comm.ServerChannel(sock_b)
            sock_a.close()

            # Replace root logger early (to capture any errors during setup)
            replace_logging(PrivsepLogHandler(channel,
                                              processName=str(context)))

            Daemon(channel, context=context).run()
            LOG.debug('privsep daemon exiting')
            os._exit(0)

        # parent

        sock_b.close()
        super().__init__(sock_a, context)
        self.exchange_ping()


class RootwrapClientChannel(_ClientChannel):
    def __init__(self, context):
        """Start privsep daemon using exec() via sudo/rootwrap.

        Uses sudo/rootwrap to gain privileges.
        """
        self.context = context
        self.sock = None
        self.proc = None # Keep track of the helper process

        self.setup()
        super().__init__(self.sock, context)
        self.exchange_ping()


    def spawn_privsep_helper(self):
        listen_sock = socket.socket(socket.AF_UNIX)
        tmpdir = tempfile.mkdtemp()
        sockpath = os.path.join(tmpdir, 'privsep.sock')

        try:
            listen_sock.bind(sockpath)
            listen_sock.listen(1)
            set_cloexec(listen_sock.fileno()) # Ensure listener is CLOEXEC

            # TODO(jules): Determine if privsep-helper needs a new CLI arg
            # like --daemon-type=rootwrap for this channel vs MACClientChannel.
            # For now, context.helper_command is generic.
            cmd = self.context.helper_command(sockpath)
            LOG.info('Running privsep helper (rootwrap): %s', cmd)
            # Note: preexec_fn=os.setpgrp to run in new process group,
            # though not strictly necessary for rootwrap if not managing it closely.
            self.proc = subprocess.Popen(cmd, shell=False, stderr=_fd_logger())

            # Wait for the helper to connect back or exit
            # A timeout here might be useful.
            conn_sock, _addr = listen_sock.accept()
            LOG.debug('Accepted privsep connection to %s from rootwrap helper', sockpath)

            # Check if helper process exited prematurely
            if self.proc.poll() is not None:
                # Process terminated, check return code
                if self.proc.returncode != 0:
                    msg = ('privsep helper command exited non-zero (%s) during connect' %
                           self.proc.returncode)
                    LOG.critical(msg)
                    conn_sock.close() # Close connection before raising
                    raise FailedToDropPrivileges(msg)
                else: # Should not happen if it exited cleanly before connect
                    LOG.warning("privsep helper exited with 0 before connect completed.")
                    conn_sock.close()
                    raise FailedToDropPrivileges("privsep helper exited prematurely")


            self.sock = conn_sock
            set_cloexec(self.sock.fileno())

        finally:
            listen_sock.close()
            try:
                os.unlink(sockpath)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    LOG.warning("Failed to unlink %s: %s", sockpath, e)
            try:
                os.rmdir(tmpdir)
            except OSError as e:
                if e.errno != errno.ENOENT and e.errno != errno.ENOTEMPTY :
                    LOG.warning("Failed to rmdir %s: %s", tmpdir, e)

        # Check if the process started successfully after connection established
        if self.proc.poll() is not None:
             if self.proc.returncode != 0:
                msg = ('privsep helper command exited non-zero (%s) immediately after connect' %
                       self.proc.returncode)
                LOG.critical(msg)
                if self.sock:
                    self.sock.close()
                raise FailedToDropPrivileges(msg)


    def setup(self):
        """Sets up the client channel by spawning the helper."""
        if self.sock is None:
            self.spawn_privsep_helper()

    def stop(self):
        """Stops the client channel and helper process."""
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.proc and self.proc.poll() is None: # if process is running
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5) # Give it a moment to terminate
            except subprocess.TimeoutExpired:
                LOG.warning("Privsep helper (rootwrap) did not terminate gracefully, sending SIGKILL.")
                self.proc.kill()
            except Exception as e:
                LOG.error("Error terminating privsep helper (rootwrap): %s", e)
            self.proc = None
        LOG.info('Rootwrap privsep channel stopped.')

    def close(self):
        self.stop()
        super().close()


class MACClientChannel(_ClientChannel):
    """Client channel for FreeBSD MAC method."""
    def __init__(self, context):
        self.context = context
        self.sock = None
        self.proc = None # Keep track of the helper process

        self.setup()
        super().__init__(self.sock, context)
        self.exchange_ping()

    def spawn_privsep_helper(self):
        """
        Spawns the privsep-helper.
        The exact command and environment for MAC-based privilege separation
        might need refinement (e.g., using setpmac or specific user with labels).
        For now, it relies on context.helper_command() which might use sudo.
        """
        listen_sock = socket.socket(socket.AF_UNIX)
        tmpdir = tempfile.mkdtemp()
        sockpath = os.path.join(tmpdir, 'privsep.sock')

        try:
            listen_sock.bind(sockpath)
            listen_sock.listen(1)
            set_cloexec(listen_sock.fileno())

            # TODO(jules): The command from helper_command() might need adjustment
            # for MAC. For example, instead of plain 'sudo', it might need
            # 'sudo -u mac_privileged_user' or a specific tool like 'setpmac'.
            # This depends on how MAC policies are configured on the system.
            # It's also possible privsep-helper needs a new CLI arg like
            # --daemon-type=mac to tell it to instantiate MACDaemon.
            cmd = self.context.helper_command(sockpath)
            # Add --daemon-type=mac to the command for privsep-helper
            cmd_mac = cmd + ['--daemon-type', 'mac']
            LOG.info('Running privsep helper (MAC): %s', cmd_mac)

            # or be handled by the command itself (e.g. sudo to a user with labels)
            self.proc = subprocess.Popen(cmd_mac, shell=False, stderr=_fd_logger())

            conn_sock, _addr = listen_sock.accept()
            LOG.debug('Accepted privsep connection to %s from MAC helper', sockpath)

            if self.proc.poll() is not None:
                if self.proc.returncode != 0:
                    msg = ('privsep helper (MAC) command exited non-zero (%s) during connect' %
                           self.proc.returncode)
                    LOG.critical(msg)
                    conn_sock.close()
                    raise FailedToDropPrivileges(msg)
                else:
                    LOG.warning("privsep helper (MAC) exited with 0 before connect completed.")
                    conn_sock.close()
                    raise FailedToDropPrivileges("privsep helper (MAC) exited prematurely")

            self.sock = conn_sock
            set_cloexec(self.sock.fileno())

        finally:
            listen_sock.close()
            try:
                os.unlink(sockpath)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    LOG.warning("Failed to unlink %s: %s", sockpath, e)
            try:
                os.rmdir(tmpdir)
            except OSError as e:
                if e.errno != errno.ENOENT and e.errno != errno.ENOTEMPTY :
                    LOG.warning("Failed to rmdir %s: %s", tmpdir, e)

        if self.proc.poll() is not None:
             if self.proc.returncode != 0:
                msg = ('privsep helper (MAC) command exited non-zero (%s) immediately after connect' %
                       self.proc.returncode)
                LOG.critical(msg)
                if self.sock:
                    self.sock.close()
                raise FailedToDropPrivileges(msg)


    def setup(self):
        """Sets up the client channel by spawning the helper."""
        if self.sock is None:
            self.spawn_privsep_helper()

    def stop(self):
        """Stops the client channel and helper process."""
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                LOG.warning("Privsep helper (MAC) did not terminate gracefully, sending SIGKILL.")
                self.proc.kill()
            except Exception as e:
                LOG.error("Error terminating privsep helper (MAC): %s", e)
            self.proc = None
        LOG.info('MAC privsep channel stopped.')

    def close(self):
        self.stop()
        super().close()


class Daemon:
    """Base class for privsep daemons.
    NB: This doesn't fork() - do that yourself before calling run()"""

    def __init__(self, channel, context):
        self.channel = channel
        self.context = context
        self.thread_pool = futures.ThreadPoolExecutor(
            context.conf.thread_pool_size)
        self.communication_error = None

    def setup(self):
        """Basic environment setup for the daemon."""
        os.chdir("/")
        os.umask(0)
        self._set_process_privileges()
        self._close_stdio()

    def run(self):
        """Run request loop. Sets up environment, then calls loop()"""
        self.setup()
        self.loop()

    def _close_stdio(self):
        # stderr is left untouched by default, allowing logs from here to escape
        # if not otherwise redirected by the calling process (e.g. _fd_logger in channels)
        with open(os.devnull, 'w+') as devnull:
            os.dup2(devnull.fileno(), StdioFd.STDIN)
            # Only redirect stdout if it's not our logging fd (if stderr is used for that)
            # or if some specific logging setup for daemon indicates otherwise.
            # For now, let's assume stdout can also go to devnull unless stderr is used for primary output.
            if StdioFd.STDOUT != sys.stderr.fileno(): # Basic check
                 os.dup2(devnull.fileno(), StdioFd.STDOUT)


    def _set_process_privileges(self):
        """Sets UID, GID, and capabilities for the daemon process."""
        user = self.context.conf.user
        group = self.context.conf.group
        caps = set(self.context.conf.capabilities)

        try:
            # Keep current capabilities across setuid away from root.
            capabilities.set_keepcaps(True)

            if group is not None:
                try:
                    os.setgroups([])
                except OSError:
                    msg = _('Failed to remove supplemental groups')
                    LOG.critical(msg)
                    raise FailedToDropPrivileges(msg)
                setgid(group)

            if user is not None:
                setuid(user)

        finally:
            capabilities.set_keepcaps(False)

        LOG.info('privsep process running with uid/gid: %(uid)s/%(gid)s',
                 {'uid': os.getuid(), 'gid': os.getgid()})

        capabilities.drop_all_caps_except(caps, caps, [])

        def fmt_caps(capset):
            if not capset:
                return 'none'
            fc = [capabilities.CAPS_BYVALUE.get(c, str(c))
                  for c in capset]
            fc.sort()
            return '|'.join(fc)

        eff, prm, inh = capabilities.get_caps()
        LOG.info(
            'privsep process running with capabilities '
            '(eff/prm/inh): %(eff)s/%(prm)s/%(inh)s',
            {
                'eff': fmt_caps(eff),
                'prm': fmt_caps(prm),
                'inh': fmt_caps(inh),
            })

    def handle_command(self, msgid, cmd, *args):
        """Executes the requested command.

        Can be overridden by subclasses for different command processing.
        This default implementation handles PING and CALL messages.
        """
        if cmd == comm.Message.PING:
            return (comm.Message.PONG.value,)

        if cmd == comm.Message.CALL:
            name, f_args, f_kwargs = args
            try:
                func = importutils.import_class(name)
                if not self.context.is_entrypoint(func):
                    msg = _('Invalid privsep function: %s not exported by context %s') % (
                        name, self.context.pypath or self.context.cfg_section)
                    raise NameError(msg)

                ret = func(*f_args, **f_kwargs)
                return (comm.Message.RET.value, ret)
            except Exception as e:
                LOG.debug(
                    'privsep: Exception during CALL[%(msgid)s] %(name)s: %(err)s',
                    {'msgid': msgid, 'name': name, 'err': e}, exc_info=True)
                cls = e.__class__
                cls_name = '{}.{}'.format(cls.__module__, cls.__name__)
                return (comm.Message.ERR.value, cls_name, e.args,
                        traceback.format_exc())
        else:
            raise ProtocolError(_('Unknown privsep cmd: %s') % cmd)


    def _create_done_callback(self, msgid):
        """Creates a future callback to send command execution results back.

        :param msgid: The message identifier.
        :return: A future reply callback.
        """
        channel = self.channel

        def _call_back(result):
            """Future execution callback.

            :param result: The `future` execution and its results.
            """
            try:
                reply = result.result()
                LOG.debug('privsep: reply[%(msgid)s]: %(reply)s',
                          {'msgid': msgid, 'reply': reply})
                channel.send((msgid, reply))
            except OSError:
                self.communication_error = sys.exc_info()
            except Exception as e:
                LOG.debug(
                    'privsep: Exception during request[%(msgid)s]: '
                    '%(err)s', {'msgid': msgid, 'err': e}, exc_info=True)
                cls = e.__class__
                cls_name = '{}.{}'.format(cls.__module__, cls.__name__)
                reply = (comm.Message.ERR.value, cls_name, e.args,
                         traceback.format_exc())
                try:
                    channel.send((msgid, reply))
                except OSError as exc:
                    self.communication_error = exc

        return _call_back

    def loop(self):
        """Main body of daemon request loop"""
        LOG.info('privsep daemon running as pid %s', os.getpid())

        # We *are* this context now - any calls through it should be
        # executed locally.
        self.context.set_client_mode(False)

        for msgid, msg in self.channel:
            if self.communication_error:
                if self.communication_error.errno == errno.EPIPE:
                    LOG.info("Client disconnected (EPIPE), exiting privsep loop.")
                    break # Write stream closed, exit loop
                raise self.communication_error # Other communication error

            # Submit the command for execution
            future = self.thread_pool.submit(self.handle_command, msgid, *msg)
            future.add_done_callback(self._create_done_callback(msgid))

        LOG.debug('Socket closed or communication error, shutting down privsep daemon')
        self.thread_pool.shutdown() # Clean up thread pool


class MACDaemon(Daemon):
    """Daemon variant for FreeBSD MAC Framework."""

    def _setup_mac_environment(self):
        """Sets the MAC label for the daemon process.

        Placeholder: Actual implementation will involve getting the target label
        from configuration (via self.context) and using mac_framework functions.
        """
        target_label = self.context.conf.mac_daemon_label
        if target_label:
            if mac_framework.libmac is None:
                LOG.error("MAC framework (libmac) not loaded. Cannot set MAC label. "
                          "Ensure this is running on a MAC-enabled FreeBSD system.")
                # Depending on policy, this might be a critical failure.
                # For now, log an error and continue; privileges might still be
                # managed by UID/GID/Capabilities if MAC isn't enforcing.
                # Consider raising FailedToDropPrivileges if MAC is mandatory.
                return

            try:
                LOG.info("Attempting to set MAC process label to: %s", target_label)
                mac_framework.mac_set_proc(target_label)
                # Verify by getting the label, if possible and desired
                current_label_obj = mac_framework.mac_get_proc()
                current_label_text = mac_framework.mac_to_text(current_label_obj)
                mac_framework.mac_free(current_label_obj)
                if current_label_text == target_label:
                    LOG.info("Successfully set and verified MAC process label: %s", current_label_text)
                else:
                    # This case might indicate that the set operation was silently ignored
                    # or modified by the system/policy.
                    LOG.warning("MAC process label after set ('%s') does not match target ('%s'). "
                                "This may be due to policy restrictions.",
                                current_label_text, target_label)
            except OSError as e:
                LOG.error("Failed to set MAC process label to '%s': %s. Check MAC policies and permissions.",
                          target_label, e)
                # Depending on the strictness required, this could raise an exception.
                # For example: raise FailedToDropPrivileges(f"Failed to set MAC label '{target_label}': {e}")
                # If the system MUST run with this label, this is a critical failure.
            except Exception as e: # Catch other potential errors from mac_framework calls
                LOG.error("An unexpected error occurred while setting MAC process label to '%s': %s",
                          target_label, e)
        else:
            LOG.info("No 'mac_daemon_label' configured for context '%s'. "
                     "Daemon will run with its default/inherited MAC label.", self.context.cfg_section)

    def setup(self):
        """Sets up the MAC daemon environment."""
        # First, perform MAC-specific setup
        self._setup_mac_environment()

        # Then, call the parent setup to handle generic daemon setup like
        # dropping privileges (UID/GID/caps) and closing stdio.
        super().setup()
        LOG.info("MACDaemon setup complete.")

    # handle_command can be inherited from Daemon if no MAC-specific handling is needed.


# Mapping of daemon types to classes for privsep-helper
DAEMON_TYPE_MAP = {
    'default': Daemon, # Generic daemon
    'mac': MACDaemon,
    # 'rootwrap': Daemon, # Rootwrap uses the default Daemon class internally
}


def helper_main():
    """Start privileged process, serving requests over a Unix socket."""

    cli_opts = [
        cfg.StrOpt('privsep_context', required=True,
                   help='Python path to the PrivContext object.'),
        cfg.StrOpt('privsep_sock_path', required=True,
                   help='Path to the Unix domain socket for communication.'),
        cfg.StrOpt('daemon_type', default='default',
                   choices=list(DAEMON_TYPE_MAP.keys()),
                   help='Type of daemon to run (e.g., default, mac). '
                        'This allows privsep-helper to start the correct '
                        'daemon subclass if needed.')
    ]
    cfg.CONF.register_cli_opts(cli_opts)

    logging.register_options(cfg.CONF)

    cfg.CONF(args=sys.argv[1:], project='privsep')
    # note replace_logging call below
    logging.setup(cfg.CONF, 'privsep', fix_eventlet=False)

    context = importutils.import_class(cfg.CONF.privsep_context)
    from oslo_privsep import priv_context   # Avoid circular import
    if not isinstance(context, priv_context.PrivContext):
        LOG.fatal('--privsep_context must be the (python) name of a '
                  'PrivContext object')
        sys.exit(1) # Ensure exit on fatal error

    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.connect(cfg.CONF.privsep_sock_path)
    except socket.error as e:
        LOG.fatal("Failed to connect to socket %s: %s", cfg.CONF.privsep_sock_path, e)
        sys.exit(1)

    set_cloexec(sock)
    channel = comm.ServerChannel(sock)

    # Channel is set up, so fork off daemon "in the background" and exit
    # This first fork is to detach from the invoking process (e.g. sudo)
    if os.fork() != 0:
        # parent
        os._exit(0) # Use _exit to avoid running atexit handlers from parent

    # child (soon to be the daemon process)

    # Note we don't move into a new process group/session like a
    # regular daemon might, since we _want_ to remain associated with
    # the originating (unprivileged) process's lifecycle indirectly.
    # os.setsid() # Uncomment if full daemonization (new session) is desired.

    # Channel is set up now, so move to in-band logging via the channel
    replace_logging(PrivsepLogHandler(channel, processName=f"privsep-helper[{os.getpid()}]"))

    LOG.info('privsep daemon (type: %s) starting with context: %s',
             cfg.CONF.daemon_type, cfg.CONF.privsep_context)

    DaemonClass = DAEMON_TYPE_MAP.get(cfg.CONF.daemon_type, Daemon)

    try:
        daemon_instance = DaemonClass(channel, context)
        daemon_instance.run()
    except Exception as e:
        LOG.exception("Unhandled exception in privsep daemon: %s", e) # Log full traceback
        # Attempt to send error to client if channel is still usable
        try:
            cls_name = '{}.{}'.format(e.__class__.__module__, e.__class__.__name__)
            error_reply = (comm.Message.ERR.value, cls_name, e.args, traceback.format_exc())
            # Use a direct send, as the loop/callback mechanism is bypassed here
            channel.send((None, error_reply)) # msgid is None as it's an out-of-band error
        except Exception as send_e:
            LOG.error("Failed to send final error to client: %s", send_e)
        sys.exit(str(e)) # Exit with error message

    LOG.info('privsep daemon (type: %s) exiting cleanly.', cfg.CONF.daemon_type)
    sys.exit(0)


if __name__ == '__main__':
    # This check ensures that helper_main() is called only when the script
    # is executed directly, not when imported as a module.
    # This is important if other parts of oslo_privsep might import daemon.py.
    helper_main()
