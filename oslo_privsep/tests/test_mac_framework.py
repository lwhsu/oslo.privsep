# Copyright 2023 The OpenStack Foundation.
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

import unittest
from unittest import mock
import os
import errno
import cffi

# Module to be tested
from oslo_privsep import mac_framework


# Helper to simulate ffi.NULL more easily if needed in many places,
# though direct use of mock_libmac.ffi.NULL is also fine.
class MockFFINULL:
    pass

MOCK_FFI_NULL = MockFFINULL()


@mock.patch.object(mac_framework, 'ffi', wraps=mac_framework.ffi) # Keep real ffi for some parts
@mock.patch.object(mac_framework, 'libc')
@mock.patch.object(mac_framework, 'libmac')
class TestMacFrameworkApiWrappers(unittest.TestCase):

    def setUp(self):
        super().setUp()
        # Ensure ffi.errno is available on the mock_libmac if libmac itself is mocked.
        # If mac_framework.libmac is None initially in tests, this might not be needed
        # until it's assigned a MagicMock.
        # For tests where libmac is mocked to a MagicMock instance:
        if isinstance(self.libmac, mock.MagicMock):
             # Create a mock ffi attribute on libmac if it doesn't exist
            if not hasattr(self.libmac, 'ffi'):
                self.libmac.ffi = mock.MagicMock()
            self.libmac.ffi.NULL = MOCK_FFI_NULL # Consistent NULL value for tests
            self.libmac.ffi.errno = 0 # Default to no error

        if isinstance(self.libc, mock.MagicMock):
            if not hasattr(self.libc, 'ffi'):
                 self.libc.ffi = mock.MagicMock()
            self.libc.ffi.NULL = MOCK_FFI_NULL
            self.libc.ffi.errno = 0


    # ===== mac_free =====
    def test_mac_free_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_ptr = mock.MagicMock(name="mac_ptr")
        mac_framework.mac_free(mock_mac_ptr)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_ptr)

    def test_mac_free_null_ptr(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.mac_free(MOCK_FFI_NULL)
        mock_libmac.mac_free.assert_not_called()

    def test_mac_free_none_ptr(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.mac_free(None)
        mock_libmac.mac_free.assert_not_called()

    def test_mac_free_libmac_none(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.libmac = None # Simulate libmac not loaded
        mock_mac_ptr = mock.MagicMock(name="mac_ptr")
        with self.assertRaisesRegex(OSError, "MAC framework not available") as cm:
            mac_framework.mac_free(mock_mac_ptr)
        self.assertEqual(cm.exception.errno, errno.ENOSYS)
        mac_framework.libmac = mock_libmac # Restore for other tests


    # ===== mac_from_text =====
    def test_mac_from_text_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_label_obj = mock.MagicMock(name="mac_label_obj")
        # Simulate ffi.new("mac_t *") returning a pointer object
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_label_obj

        mock_libmac.mac_from_text.return_value = 0 # Success

        returned_label = mac_framework.mac_from_text("biba/low")

        mock_ffi_obj.new.assert_any_call("char[]", b"biba/low") # from _encode_string
        mock_ffi_obj.new.assert_any_call("mac_t *")
        mock_libmac.mac_from_text.assert_called_once()
        self.assertEqual(returned_label, mock_mac_label_obj)

    def test_mac_from_text_failure(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_libmac.mac_from_text.return_value = -1 # Failure
        mock_libmac.ffi.errno = errno.EINVAL

        with self.assertRaisesRegex(OSError, "Failed to convert label 'biba/low' from text"):
            mac_framework.mac_from_text("biba/low")
        self.assertEqual(mock_libmac.ffi.errno, errno.EINVAL)

    def test_mac_from_text_libmac_none(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.libmac = None
        with self.assertRaisesRegex(OSError, "MAC framework not available"):
            mac_framework.mac_from_text("biba/low")
        mac_framework.libmac = mock_libmac


    # ===== mac_to_text =====
    def test_mac_to_text_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_ptr = mock.MagicMock(name="mac_ptr")
        mock_text_ptr = mock.MagicMock(name="text_ptr")
        mock_text_ptr_ptr = mock_ffi_obj.new.return_value
        mock_text_ptr_ptr.__getitem__.return_value = mock_text_ptr

        mock_libmac.mac_to_text.return_value = 0 # Success

        # Simulate ffi.string() behavior for _decode_string
        mock_ffi_obj.string.return_value = b"biba/high"

        returned_text = mac_framework.mac_to_text(mock_mac_ptr)

        mock_ffi_obj.new.assert_called_once_with("char **")
        mock_libmac.mac_to_text.assert_called_once_with(mock_mac_ptr, mock_text_ptr_ptr)
        mock_ffi_obj.string.assert_called_once_with(mock_text_ptr)
        mock_libc.free.assert_called_once_with(mock_text_ptr)
        self.assertEqual(returned_text, "biba/high")

    def test_mac_to_text_failure(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_ptr = mock.MagicMock(name="mac_ptr")
        mock_text_ptr_ptr = mock_ffi_obj.new.return_value
        mock_text_ptr_ptr.__getitem__.return_value = MOCK_FFI_NULL # Ensure free is not called on NULL

        mock_libmac.mac_to_text.return_value = -1 # Failure
        mock_libmac.ffi.errno = errno.EACCES

        with self.assertRaisesRegex(OSError, "Failed to convert MAC label to text"):
            mac_framework.mac_to_text(mock_mac_ptr)

        mock_libc.free.assert_called_once_with(MOCK_FFI_NULL) # free(NULL) is safe
        self.assertEqual(mock_libmac.ffi.errno, errno.EACCES)


    def test_mac_to_text_libmac_none(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.libmac = None
        with self.assertRaisesRegex(OSError, "MAC framework not available"):
            mac_framework.mac_to_text(mock.MagicMock())
        mac_framework.libmac = mock_libmac

    def test_mac_to_text_libc_none(self, mock_libmac, mock_libc, mock_ffi_obj):
        mac_framework.libc = None
        with self.assertRaisesRegex(OSError, "Standard C library not available"):
            mac_framework.mac_to_text(mock.MagicMock())
        mac_framework.libc = mock_libc


    # ===== mac_get_proc =====
    def test_mac_get_proc_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_process_label.return_value = 0
        mock_libmac.mac_get_proc.return_value = 0

        result = mac_framework.mac_get_proc()

        mock_ffi_obj.new.assert_called_once_with("mac_t *")
        mock_libmac.mac_prepare_process_label.assert_called_once_with(mock_mac_ptr_ptr)
        mock_libmac.mac_get_proc.assert_called_once_with(mock_mac_obj)
        self.assertEqual(result, mock_mac_obj)
        mock_libmac.mac_free.assert_not_called() # User must free

    def test_mac_get_proc_prepare_failure(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_ffi_obj.new.return_value = mock.MagicMock() # dummy mac_ptr_ptr
        mock_libmac.mac_prepare_process_label.return_value = -1
        mock_libmac.ffi.errno = errno.ENOMEM

        with self.assertRaisesRegex(OSError, "Failed to prepare process MAC label"):
            mac_framework.mac_get_proc()
        mock_libmac.mac_free.assert_not_called() # Not prepared, so not freed

    def test_mac_get_proc_get_failure(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_process_label.return_value = 0
        mock_libmac.mac_get_proc.return_value = -1
        mock_libmac.ffi.errno = errno.EPERM

        with self.assertRaisesRegex(OSError, "Failed to get process MAC label"):
            mac_framework.mac_get_proc()
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj) # Freed on failure


    # ===== mac_set_proc =====
    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_proc_success(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        mock_libmac.mac_set_proc.return_value = 0
        label_text = "test/label"

        mac_framework.mac_set_proc(label_text)

        mock_mac_from_text.assert_called_once_with(label_text)
        mock_libmac.mac_set_proc.assert_called_once_with(mock_mac_obj)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)


    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_proc_failure_on_set(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        mock_libmac.mac_set_proc.return_value = -1 # Error on set
        mock_libmac.ffi.errno = errno.EACCES
        label_text = "test/label"

        with self.assertRaisesRegex(OSError, "Failed to set process MAC label"):
            mac_framework.mac_set_proc(label_text)

        mock_mac_from_text.assert_called_once_with(label_text)
        mock_libmac.mac_set_proc.assert_called_once_with(mock_mac_obj)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj) # Ensure free even on failure

    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_proc_failure_on_from_text(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_from_text.side_effect = OSError(errno.EINVAL, "Conversion failed")
        label_text = "invalidlabel"

        with self.assertRaisesRegex(OSError, "Conversion failed"):
            mac_framework.mac_set_proc(label_text)

        mock_libmac.mac_set_proc.assert_not_called()
        mock_libmac.mac_free.assert_not_called() # mac_obj not created


    # ===== mac_get_file =====
    def test_mac_get_file_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value # For mac_prepare_file_label
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_encoded_path = mock.MagicMock(name="encoded_path")
        mock_ffi_obj.new.side_effect = [mock_mac_ptr_ptr, mock_encoded_path]


        mock_libmac.mac_prepare_file_label.return_value = 0
        mock_libmac.mac_get_file.return_value = 0
        path = "/tmp/somefile"

        result = mac_framework.mac_get_file(path)

        mock_ffi_obj.new.assert_any_call("mac_t *")
        mock_ffi_obj.new.assert_any_call("char[]", path.encode())
        mock_libmac.mac_prepare_file_label.assert_called_once_with(mock_mac_ptr_ptr)
        mock_libmac.mac_get_file.assert_called_once_with(mock_encoded_path, mock_mac_obj)
        self.assertEqual(result, mock_mac_obj)
        mock_libmac.mac_free.assert_not_called()

    def test_mac_get_file_not_found(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj
        mock_ffi_obj.new.side_effect = [mock_mac_ptr_ptr, mock.MagicMock()] # path

        mock_libmac.mac_prepare_file_label.return_value = 0
        mock_libmac.mac_get_file.return_value = -1 # Error
        mock_libmac.ffi.errno = errno.ENOENT # File not found
        path = "/tmp/nonexistent"

        with self.assertRaises(FileNotFoundError):
            mac_framework.mac_get_file(path)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)

    # ===== mac_set_file =====
    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_file_success(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        mock_encoded_path = mock.MagicMock(name="encoded_path")
        mock_ffi_obj.new.return_value = mock_encoded_path # For _encode_string

        mock_libmac.mac_set_file.return_value = 0
        path = "/tmp/somefile"
        label_text = "test/label"

        mac_framework.mac_set_file(path, label_text)

        mock_mac_from_text.assert_called_once_with(label_text)
        mock_ffi_obj.new.assert_called_once_with("char[]", path.encode())
        mock_libmac.mac_set_file.assert_called_once_with(mock_encoded_path, mock_mac_obj)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)

    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_file_not_found(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        # ... (setup for _encode_string if its call is asserted)

        mock_libmac.mac_set_file.return_value = -1
        mock_libmac.ffi.errno = errno.ENOENT
        path = "/tmp/nonexistent"

        with self.assertRaises(FileNotFoundError):
            mac_framework.mac_set_file(path, "test/label")
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)

    # ===== mac_get_fd =====
    def test_mac_get_fd_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_file_label.return_value = 0 # Assumed preparation
        mock_libmac.mac_get_fd.return_value = 0
        fd = 5

        result = mac_framework.mac_get_fd(fd)

        mock_ffi_obj.new.assert_called_once_with("mac_t *")
        mock_libmac.mac_prepare_file_label.assert_called_once_with(mock_mac_ptr_ptr)
        mock_libmac.mac_get_fd.assert_called_once_with(fd, mock_mac_obj)
        self.assertEqual(result, mock_mac_obj)
        mock_libmac.mac_free.assert_not_called()


    def test_mac_get_fd_failure_on_get(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_file_label.return_value = 0
        mock_libmac.mac_get_fd.return_value = -1 # Error
        mock_libmac.ffi.errno = errno.EBADF
        fd = -1 # Invalid FD

        with self.assertRaisesRegex(OSError, "Failed to get MAC label for fd"):
            mac_framework.mac_get_fd(fd)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)


    # ===== mac_set_fd =====
    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_fd_success(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        mock_libmac.mac_set_fd.return_value = 0
        fd = 5
        label_text = "test/label"

        mac_framework.mac_set_fd(fd, label_text)

        mock_mac_from_text.assert_called_once_with(label_text)
        mock_libmac.mac_set_fd.assert_called_once_with(fd, mock_mac_obj)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)


    # ===== mac_get_link =====
    def test_mac_get_link_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value # For mac_prepare_file_label
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj
        mock_encoded_path = mock.MagicMock(name="encoded_path")
        # Ensure ffi.new is versatile for multiple calls in one test function
        mock_ffi_obj.new.side_effect = lambda type_str, *args: \
            mock_mac_ptr_ptr if type_str == "mac_t *" else \
            (mock_encoded_path if type_str == "char[]" else mock.DEFAULT)

        mock_libmac.mac_prepare_file_label.return_value = 0
        mock_libmac.mac_get_link.return_value = 0
        path = "/tmp/somelink"

        result = mac_framework.mac_get_link(path)

        # Check calls were made
        mock_ffi_obj.new.assert_any_call("mac_t *")
        mock_ffi_obj.new.assert_any_call("char[]", path.encode())
        mock_libmac.mac_prepare_file_label.assert_called_once_with(mock_mac_ptr_ptr)
        mock_libmac.mac_get_link.assert_called_once_with(mock_encoded_path, mock_mac_obj)
        self.assertEqual(result, mock_mac_obj)

    # ===== mac_set_link =====
    @mock.patch.object(mac_framework, 'mac_from_text')
    def test_mac_set_link_success(self, mock_mac_from_text, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_from_text.return_value = mock_mac_obj
        mock_encoded_path = mock.MagicMock(name="encoded_path")
        mock_ffi_obj.new.return_value = mock_encoded_path # For _encode_string

        mock_libmac.mac_set_link.return_value = 0
        path = "/tmp/somelink"
        label_text = "test/label"

        mac_framework.mac_set_link(path, label_text)
        mock_libmac.mac_set_link.assert_called_once_with(mock_encoded_path, mock_mac_obj)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)


    # ===== mac_get_peer =====
    def test_mac_get_peer_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_ifnet_label.return_value = 0 # Assumed preparation
        mock_libmac.mac_get_peer.return_value = 0
        fd = 5 # Socket fd

        result = mac_framework.mac_get_peer(fd)

        mock_ffi_obj.new.assert_called_once_with("mac_t *")
        mock_libmac.mac_prepare_ifnet_label.assert_called_once_with(mock_mac_ptr_ptr)
        mock_libmac.mac_get_peer.assert_called_once_with(fd, mock_mac_obj)
        self.assertEqual(result, mock_mac_obj)


    # ===== mac_get_pid =====
    def test_mac_get_pid_success(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_process_label.return_value = 0
        mock_libmac.mac_get_pid.return_value = 0
        pid = 1234

        result = mac_framework.mac_get_pid(pid)
        self.assertEqual(result, mock_mac_obj)

    def test_mac_get_pid_process_not_found(self, mock_libmac, mock_libc, mock_ffi_obj):
        mock_mac_obj = mock.MagicMock(name="mac_obj")
        mock_mac_ptr_ptr = mock_ffi_obj.new.return_value
        mock_mac_ptr_ptr.__getitem__.return_value = mock_mac_obj

        mock_libmac.mac_prepare_process_label.return_value = 0
        mock_libmac.mac_get_pid.return_value = -1 # Error
        mock_libmac.ffi.errno = errno.ESRCH # Process not found
        pid = 99999

        with self.assertRaises(ProcessLookupError):
            mac_framework.mac_get_pid(pid)
        mock_libmac.mac_free.assert_called_once_with(mock_mac_obj)


if __name__ == '__main__':
    unittest.main()
