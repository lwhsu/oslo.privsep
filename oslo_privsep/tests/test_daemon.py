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

import copy
import eventlet
import fixtures
import functools
import logging as pylogging
import sys
import time
from unittest import mock

from oslo_log import formatters
from oslo_log import log as logging
from oslotest import base

from oslo_privsep import capabilities
from oslo_privsep import comm
from oslo_privsep import daemon
from oslo_privsep.tests import testctx


LOG = logging.getLogger(__name__)


def undecorated():
    pass


class TestException(Exception):
    pass


def get_fake_context(conf_attrs=None, **context_attrs):
    conf_attrs = conf_attrs or {}
    context = mock.NonCallableMock()
    context.conf.user = 42
    context.conf.group = 84
    context.conf.thread_pool_size = 10
    context.conf.capabilities = [
        capabilities.CAP_SYS_ADMIN, capabilities.CAP_NET_ADMIN]
    context.conf.logger_name = 'oslo_privsep.daemon'
    vars(context).update(context_attrs)
    vars(context.conf).update(conf_attrs)
    return context


@testctx.context.entrypoint
def logme(level, msg, exc_info=False):
    # We want to make sure we log everything from the priv side for
    # the purposes of this test, so force loglevel.
    LOG.logger.setLevel(logging.DEBUG)
    if exc_info:
        try:
            raise TestException('with arg')
        except TestException:
            LOG.log(level, msg, exc_info=True)
    else:
        LOG.log(level, msg)


@testctx.context.entrypoint
def raise_runtimeerror():
    raise RuntimeError()


class LogRecorder(pylogging.Formatter):
    def __init__(self, logs, *args, **kwargs):
        kwargs['validate'] = False
        super().__init__(*args, **kwargs)
        self.logs = logs

    def format(self, record):
        self.logs.append(copy.deepcopy(record))
        return super().format(record)


class LogTest(testctx.TestContextTestCase):
    def test_priv_loglevel(self):
        logger = self.useFixture(fixtures.FakeLogger(
            level=logging.INFO))

        # These write to the log on the priv side
        logme(logging.DEBUG, 'test@DEBUG')
        logme(logging.WARN, 'test@WARN')

        time.sleep(0.1)  # Hack to give logging thread a chance to run

        # logger.output is the resulting log on the unpriv side.
        # This should have been filtered based on (unpriv) loglevel.
        self.assertNotIn('test@DEBUG', logger.output)
        self.assertIn('test@WARN', logger.output)

    def test_record_data(self):
        logs = []

        self.useFixture(fixtures.FakeLogger(
            level=logging.INFO, format='dummy',
            # fixtures.FakeLogger accepts only a formatter
            # class/function, not an instance :(
            formatter=functools.partial(LogRecorder, logs)))

        try:
            logme(logging.WARN, 'test with exc', exc_info=True)
        except Exception:
            pass

        time.sleep(0.1)  # Hack to give logging thread a chance to run

        self.assertEqual(1, len(logs))

        record = logs[0]
        self.assertIn('test with exc', record.getMessage())
        self.assertIsNone(record.exc_info)
        self.assertIn('TestException: with arg', record.exc_text)
        self.assertEqual('PrivContext(cfg_section=privsep)',
                         record.processName)
        self.assertIn('test_daemon.py', record.exc_text)
        self.assertEqual(logging.WARN, record.levelno)
        self.assertEqual('logme', record.funcName)

    def test_format_record(self):
        logs = []

        self.useFixture(fixtures.FakeLogger(
            level=logging.INFO, format='dummy',
            # fixtures.FakeLogger accepts only a formatter
            # class/function, not an instance :(
            formatter=functools.partial(LogRecorder, logs)))

        logme(logging.WARN, 'test with exc', exc_info=True)

        time.sleep(0.1)  # Hack to give logging thread a chance to run

        self.assertEqual(1, len(logs))

        record = logs[0]
        # Verify the log record can be formatted by ContextFormatter
        fake_config = mock.Mock(
            logging_default_format_string="NOCTXT: %(message)s")
        formatter = formatters.ContextFormatter(config=fake_config)
        formatter.format(record)


class LogTestDaemonTraceback(testctx.TestContextTestCase):
    def setUp(self):
        self.config_override = {'log_daemon_traceback': True}
        super().setUp()

    def test_record_daemon_traceback(self):
        self.privsep_conf.set_override(
            'log_daemon_traceback', True, group='privsep')
        logs = []
        self.useFixture(fixtures.FakeLogger(
            level=logging.INFO, format='dummy',
            # fixtures.FakeLogger accepts only a formatter
            # class/function, not an instance :(
            formatter=functools.partial(LogRecorder, logs)))

        self.assertRaises(RuntimeError, raise_runtimeerror)
        time.sleep(0.1)  # Hack to give logging thread a chance to run

        self.assertEqual(1, len(logs))
        record = logs[0]
        self.assertIn('Privsep daemon traceback: ', record.getMessage())
        self.assertIsNone(record.exc_info)
        self.assertEqual('MainProcess', record.processName)
        self.assertEqual(logging.WARN, record.levelno)


class DaemonTest(base.BaseTestCase):

    @mock.patch('os.setuid')
    @mock.patch('os.setgid')
    @mock.patch('os.setgroups')
    @mock.patch('oslo_privsep.capabilities.set_keepcaps')
    @mock.patch('oslo_privsep.capabilities.drop_all_caps_except')
    def test_drop_privs(self, mock_dropcaps, mock_keepcaps,
                        mock_setgroups, mock_setgid, mock_setuid):
        channel = mock.NonCallableMock()
        context = get_fake_context()

        manager = mock.Mock()
        manager.attach_mock(mock_setuid, "setuid")
        manager.attach_mock(mock_setgid, "setgid")
        expected_calls = [mock.call.setgid(84), mock.call.setuid(42)]

        d = daemon.Daemon(channel, context)
        d._drop_privs()

        mock_setuid.assert_called_once_with(42)
        mock_setgid.assert_called_once_with(84)
        mock_setgroups.assert_called_once_with([])

        assert manager.mock_calls == expected_calls

        self.assertCountEqual(
            [mock.call(True), mock.call(False)],
            mock_keepcaps.mock_calls)

        mock_dropcaps.assert_called_once_with(
            {capabilities.CAP_SYS_ADMIN, capabilities.CAP_NET_ADMIN},
            {capabilities.CAP_SYS_ADMIN, capabilities.CAP_NET_ADMIN},
            [])


class WithContextTest(testctx.TestContextTestCase):

    def test_unexported(self):
        self.assertRaisesRegex(
            NameError, 'undecorated not exported',
            testctx.context._wrap, undecorated)


class ClientChannelTestCase(base.BaseTestCase):

    DICT = {
        'string_1': ('tuple_1', b'tuple_2'),
        b'byte_1': ['list_1', 'list_2'],
    }

    EXPECTED = {
        'string_1': ('tuple_1', b'tuple_2'),
        'byte_1': ['list_1', 'list_2'],
    }

    def setUp(self):
        super().setUp()
        context = get_fake_context()
        with mock.patch.object(comm.ClientChannel, '__init__'), \
                mock.patch.object(daemon._ClientChannel, 'exchange_ping'):
            self.client_channel = daemon._ClientChannel(mock.ANY, context)

    @mock.patch.object(daemon.LOG.logger, 'handle')
    def test_out_of_band_log_message(self, handle_mock):
        message = [comm.Message.LOG, self.DICT]
        self.assertEqual(self.client_channel.log, daemon.LOG)
        with mock.patch.object(pylogging, 'makeLogRecord') as mock_make_log, \
                mock.patch.object(daemon.LOG, 'isEnabledFor',
                                  return_value=True) as mock_enabled:
            self.client_channel.out_of_band(message)
            mock_make_log.assert_called_once_with(self.EXPECTED)
            handle_mock.assert_called_once_with(mock_make_log.return_value)
            mock_enabled.assert_called_once_with(
                mock_make_log.return_value.levelno)

    def test_out_of_band_not_log_message(self):
        with mock.patch.object(daemon.LOG, 'warning') as mock_warning:
            self.client_channel.out_of_band([comm.Message.PING])
            mock_warning.assert_called_once()

    @mock.patch.object(daemon.logging, 'getLogger')
    @mock.patch.object(pylogging, 'makeLogRecord')
    def test_out_of_band_log_message_context_logger(self, make_log_mock,
                                                    get_logger_mock):
        logger_name = 'os_brick.privileged'
        context = get_fake_context(conf_attrs={'logger_name': logger_name})
        with mock.patch.object(comm.ClientChannel, '__init__'), \
                mock.patch.object(daemon._ClientChannel, 'exchange_ping'):
            channel = daemon._ClientChannel(mock.ANY, context)

        get_logger_mock.assert_called_once_with(logger_name)
        self.assertEqual(get_logger_mock.return_value, channel.log)

        message = [comm.Message.LOG, self.DICT]
        channel.out_of_band(message)

        make_log_mock.assert_called_once_with(self.EXPECTED)
        channel.log.isEnabledFor.assert_called_once_with(
            make_log_mock.return_value.levelno)
        channel.log.logger.handle.assert_called_once_with(
            make_log_mock.return_value)


class UnMonkeyPatch(base.BaseTestCase):

    def test_un_monkey_patch(self):
        self.assertFalse(any(
            eventlet.patcher.is_monkey_patched(eventlet_mod_name)
            for eventlet_mod_name in daemon.EVENTLET_MODULES))

        eventlet.monkey_patch()
        self.assertTrue(any(
            eventlet.patcher.is_monkey_patched(eventlet_mod_name)
            for eventlet_mod_name in daemon.EVENTLET_MODULES))

        daemon.un_monkey_patch()
        for eventlet_mod_name, func_modules in daemon.EVENTLET_LIBRARIES:
            if not eventlet.patcher.is_monkey_patched(eventlet_mod_name):
                continue

            for name, green_mod in func_modules():
                orig_mod = eventlet.patcher.original(name)
                patched_mod = sys.modules.get(name)
                for attr_name in green_mod.__patched__:
                    un_monkey_patched_attr = getattr(patched_mod, attr_name,
                                                     None)
                    original_attr = getattr(orig_mod, attr_name, None)
                    self.assertEqual(un_monkey_patched_attr, original_attr)


@mock.patch('oslo_privsep.daemon.replace_logging') # To prevent log setup changes
@mock.patch('oslo_privsep.daemon.set_cloexec')
@mock.patch('oslo_privsep.daemon.comm.ServerChannel')
@mock.patch('socket.socket') # Mock socket interactions for helper
class TestMACDaemonIntegration(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        # Register privsep options for the test context
        # Use a unique section name to avoid conflicts if other tests use 'privsep'
        self.cfg_section = 'privsep_mac_test'
        self.conf = cfg.CONF
        self.conf.register_opts(priv_context.OPTS, group=self.cfg_section)

        # Create a PrivContext instance for testing
        # The pypath needs to be valid for the helper to import the context.
        # We can point it to a static instance in this test module if needed,
        # or mock importutils.import_class if full helper simulation is too complex.
        self.context = priv_context.PrivContext(
            prefix='oslo_privsep.tests.testctx', # Standard test context prefix
            cfg_section=self.cfg_section,
            pypath=f'{__name__}.test_context_instance' # Path to a global context for helper
        )
        # Make this context instance globally available for the fake_popen_side_effect
        global test_context_instance
        test_context_instance = self.context


    def tearDown(self):
        # Unregister opts to keep test environment clean
        self.conf.unregister_opts(priv_context.OPTS, group=self.cfg_section)
        if hasattr(self, 'context') and self.context.channel:
            self.context.stop() # Ensure channel is stopped
        super().tearDown()
        global test_context_instance
        test_context_instance = None


    @mock.patch('subprocess.Popen')
    @mock.patch.object(mac_framework, 'mac_set_proc', autospec=True)
    @mock.patch.object(mac_framework, 'mac_get_proc', autospec=True)
    @mock.patch.object(mac_framework, 'mac_to_text', autospec=True)
    # Mock libmac availability for the MACDaemon's check
    @mock.patch.object(mac_framework, 'libmac', create=True)
    def test_mac_method_starts_helper_and_sets_label(self,
                                                   mock_libmac_present, # For mac_framework.libmac
                                                   mock_mac_to_text,
                                                   mock_mac_get_proc,
                                                   mock_mac_set_proc,
                                                   mock_popen,
                                                   mock_socket, # from class decorator
                                                   mock_server_channel, # from class decorator
                                                   mock_set_cloexec, # from class decorator
                                                   mock_replace_logging # from class decorator
                                                   ):
        # Arrange
        test_label = 'biba/test_integration_label'
        self.conf.set_override('mac_daemon_label', test_label, group=self.cfg_section)
        # Ensure the context re-reads the config if it caches it (it does via self.conf)
        # No, self.context.conf directly accesses cfg.CONF[self.cfg_section]

        # Mock Popen behavior
        mock_proc_instance = mock.MagicMock(spec=subprocess.Popen)
        mock_proc_instance.pid = 12345
        mock_proc_instance.poll.return_value = None # Simulate process running initially
        mock_popen.return_value = mock_proc_instance

        # Simulate the helper side: when Popen is called with '--daemon-type mac',
        # it should trigger the MACDaemon's setup which calls mac_set_proc.
        original_import_class = daemon.importutils.import_class

        def fake_popen_side_effect(cmd, *args, **kwargs):
            # Simulate the privsep-helper main execution path for MAC daemon
            if '--daemon-type' in cmd and 'mac' in cmd:
                # Helper connects back to the client channel's listening socket.
                # The actual socket comms are complex to mock fully.
                # We assume the connection happens and focus on daemon setup.

                # Reconstruct context as helper_main would
                # The pypath 'oslo_privsep.tests.test_daemon.test_context_instance'
                # should point back to self.context for this test.
                pypath_arg_index = cmd.index('--privsep_context') + 1
                context_pypath = cmd[pypath_arg_index]

                # Mock import_class to return our specific context instance for the helper side
                with mock.patch.object(daemon.importutils, 'import_class') as mock_import_class:
                    mock_import_class.return_value = test_context_instance

                    # Simulate parts of helper_main relevant to MACDaemon instantiation and setup
                    mock_channel_for_daemon = mock.MagicMock(spec=comm.ServerChannel)

                    # Ensure libmac is "available" for the MACDaemon's check
                    mac_framework.libmac = mock_libmac_present # Use the patched libmac

                    mac_daemon_instance = daemon.MACDaemon(channel=mock_channel_for_daemon,
                                                           context=test_context_instance)
                    # Call the setup method that should trigger mac_set_proc
                    mac_daemon_instance.setup()
            return mock_proc_instance

        mock_popen.side_effect = fake_popen_side_effect

        # Mock mac_get_proc and mac_to_text for label verification part
        mock_mac_ptr = mock.MagicMock()
        mock_mac_get_proc.return_value = mock_mac_ptr
        mock_mac_to_text.return_value = test_label # Simulate label was set correctly

        # Act
        self.context.start(method=priv_context.Method.MAC)

        # Assert
        # 1. Popen was called with '--daemon-type mac'
        popen_called_with_mac_type = False
        actual_cmd_used = None
        for call_args in mock_popen.call_args_list:
            cmd_list = call_args[0][0]
            actual_cmd_used = cmd_list # Capture command for logging if assert fails
            if '--daemon-type' in cmd_list and 'mac' in cmd_list:
                popen_called_with_mac_type = True
                # Also check for privsep_context and sock_path
                self.assertIn('--privsep_context', cmd_list)
                self.assertIn(self.context.pypath, cmd_list)
                self.assertIn('--privsep_sock_path', cmd_list)
                break
        self.assertTrue(popen_called_with_mac_type,
                        f"subprocess.Popen was not called with --daemon-type mac. Called with: {actual_cmd_used}")

        # 2. mac_set_proc was called with the correct label by the simulated daemon
        mock_mac_set_proc.assert_called_once_with(test_label)

        # 3. (Optional) Check if verification calls were made if label was set
        if test_label:
            mock_mac_get_proc.assert_called_once()
            mock_mac_to_text.assert_called_once_with(mock_mac_ptr)

        # Cleanup
        self.context.stop()
        # Ensure Popen's process is "terminated" if stop was called
        if self.context.channel is None: # Check if channel was properly closed
             mock_proc_instance.terminate.assert_called()


# This global is used by fake_popen_side_effect to access the test's PrivContext instance
test_context_instance = None
