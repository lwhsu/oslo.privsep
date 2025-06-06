# Copyright 2023 Acme Corp.
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

"""
Python ctypes bindings for libmac (FreeBSD MAC Framework).

This module provides Python wrappers for the Mandatory Access Control (MAC)
framework available on FreeBSD systems. It uses CFFI to interact with the
native `libmac` C library.

Current capabilities:
- Initialization of CFFI and loading of `libmac`.
- Helper functions for string encoding/decoding between Python and C.
- Wrappers for core MAC functions:
    - `mac_free()`: Frees `mac_t` label structures.
    - `mac_from_text()`: Converts text label to `mac_t`.
    - `mac_to_text()`: Converts `mac_t` to text label (with memory management).
    - `mac_get_proc()`: Gets current process's MAC label.
    - `mac_set_proc()`: Sets current process's MAC label.
    - `mac_get_file()`: Gets a file/directory's MAC label.
    - `mac_set_file()`: Sets a file/directory's MAC label.
    - `mac_get_fd()`: Gets a file descriptor's MAC label.
    - `mac_set_fd()`: Sets a file descriptor's MAC label.
    - `mac_get_link()`: Gets a symbolic link's MAC label.
    - `mac_set_link()`: Sets a symbolic link's MAC label.
    - `mac_get_peer()`: Gets a peer socket's MAC label.
    - `mac_get_pid()`: Gets a process's MAC label by PID.
- Basic error handling, including `FileNotFoundError` and `ProcessLookupError`.
- Example usage in `if __name__ == '__main__':` block (FreeBSD specific).

Placeholders and future work:
- Mapping Linux capabilities to MAC framework policies/labels. This is a
  significant piece of work requiring careful design.
- More granular error handling and reporting for MAC-specific errors.
- Potentially wrappers for `mac_prepare()` or `mac_prepare_type()` if a
  more generic label preparation mechanism is needed beyond the specific
  `mac_prepare_*_label()` functions used.
- Verification of `mac_prepare_*_label()` usage for `mac_get_fd` and
  `mac_get_peer` (currently uses file and ifnet preparations respectively,
  which might need adjustment based on specific MAC policy requirements or
  if dedicated fd/socket preparation functions become available/necessary).

Note: This module is intended for use on FreeBSD or systems with a compatible
`libmac` implementation. Behavior on other systems is undefined, and `libmac`
will likely fail to load.
"""

import cffi
import errno
import os

# Define CFFI declarations for MAC framework APIs
CDEF = """
typedef struct mac *mac_t;

int mac_free(mac_t mac);

int mac_get_fd(int fd, mac_t mac);
int mac_get_file(const char *path, mac_t mac);
int mac_get_link(const char *path, mac_t mac);
int mac_get_peer(int fd, mac_t mac); // For sockets
int mac_get_pid(pid_t pid, mac_t mac);
int mac_get_proc(mac_t mac); // Current process

int mac_set_fd(int fd, mac_t mac);
int mac_set_file(const char *path, mac_t mac);
int mac_set_link(const char *path, mac_t mac);
int mac_set_proc(mac_t mac); // Current process

int mac_from_text(mac_t *mac, const char *text);
int mac_to_text(mac_t mac, char **text);

// Not all systems might have this, but it's good to have
// int mac_prepare(mac_t *mac, const char *elements);
// For now, we'll assume simpler label prep if mac_prepare is not standard/easy
// Or rely on mac_from_text to prepare the mac_t structure

// For mac_prepare_type functions, which might be more portable for defaults
int mac_prepare_file_label(mac_t *mac);
int mac_prepare_ifnet_label(mac_t *mac);
int mac_prepare_process_label(mac_t *mac);
// enum mac_label_type { MAC_LABEL_TYPE_IFNET, MAC_LABEL_TYPE_FILE, ...};
// int mac_prepare_type(mac_t *mac, enum mac_label_type type);


char * strerror(int errnum);
void free(void *ptr); // For freeing memory from mac_to_text
"""

# Initialize CFFI
ffi = cffi.FFI()
ffi.cdef(CDEF)
# Try to link against libc, where these symbols should reside on FreeBSD
# If this fails, it means the execution environment is not FreeBSD or
# libc doesn't contain these symbols for some reason.
# Also try to dlopen(None) for libc.free if 'c' doesn't work for some reason.
try:
    libmac = ffi.dlopen('c')
    libc = libmac # Assume libc.free is part of 'c'
except OSError:
    try:
        # Fallback for systems where 'c' might not be the name for libc
        # or if we need a separate handle for libc.free specifically.
        libc = ffi.dlopen(None)
        # If dlopen('c') failed, libmac specific symbols are not available.
        libmac = None
    except OSError:
        # This is a fallback or error indicator; ideally, this module
        # should only be used on systems where these calls are available.
        libmac = None
        libc = None

# Helper function to convert Python string to C char* and back for text functions
def _encode_string(pystr):
    if pystr is None:
        return ffi.NULL
    return ffi.new("char[]", pystr.encode())

def _decode_string(cstr):
    if cstr == ffi.NULL:
        return None
    return ffi.string(cstr).decode()

# Python wrappers for MAC framework functions

def mac_free(mac_ptr):
    """
    Frees the mac_t structure.

    Args:
        mac_ptr (cdata 'mac_t'): Pointer to the MAC label structure to be freed.

    Returns:
        int: 0 on success, or an error code from libmac.mac_free.

    Raises:
        OSError: If libmac is not available (e.g., not on FreeBSD).
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")
    if mac_ptr and mac_ptr != ffi.NULL:
        return libmac.mac_free(mac_ptr)
    return 0

def mac_from_text(text_label):
    """
    Converts a text label string to a mac_t structure.

    Args:
        text_label (str): The text representation of the MAC label.

    Returns:
        cdata 'mac_t': A pointer to the newly created MAC label structure.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_from_text` fails
                 (e.g., invalid label format). Includes the OS error number
                 and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")
    mac_ptr_ptr = ffi.new("mac_t *")
    ret = libmac.mac_from_text(mac_ptr_ptr, _encode_string(text_label))
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to convert label '{text_label}' from text")
    return mac_ptr_ptr[0] # Dereference to get mac_t

def mac_to_text(mac_ptr):
    """
    Converts a mac_t structure to a text label string.

    The memory for the returned string is allocated by the C library and
    is freed by this function after converting it to a Python string.

    Args:
        mac_ptr (cdata 'mac_t'): Pointer to the MAC label structure.

    Returns:
        str: The text representation of the MAC label.

    Raises:
        OSError: If libmac or libc is not available, or if `mac_to_text` fails.
                 Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")
    if not libc:
        raise OSError(errno.ENOSYS, "Standard C library not available for memory management")

    text_ptr_ptr = ffi.new("char **")
    ret = libmac.mac_to_text(mac_ptr, text_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), "Failed to convert MAC label to text")

    try:
        text_label = _decode_string(text_ptr_ptr[0])
    finally:
        # Free the memory allocated by mac_to_text using libc.free
        # This is crucial as text_ptr_ptr[0] is allocated by the C library.
        if text_ptr_ptr[0] != ffi.NULL:
            libc.free(text_ptr_ptr[0]) # Ensure libc is available and loaded.

    return text_label

def mac_get_proc():
    """
    Gets the MAC label of the current process.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the current process.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_process_label`
                 or `mac_get_proc` fails. Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    # Prepare a mac_t structure to hold the label
    # Using mac_prepare_process_label for default initialization
    mac_ptr_ptr = ffi.new("mac_t *")
    ret = libmac.mac_prepare_process_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), "Failed to prepare process MAC label")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_proc(mac_ptr)
        if ret != 0:
            err = ffi.errno
            raise OSError(err, os.strerror(err), "Failed to get process MAC label")
        return mac_ptr # Return the mac_t structure, user must free it
    except Exception:
        mac_free(mac_ptr) # Clean up if error
        raise

def mac_set_proc(label_text):
    """
    Sets the MAC label of the current process.

    Args:
        label_text (str): The text representation of the MAC label to set.

    Raises:
        OSError: If libmac is not available, or if `mac_from_text` or
                 `mac_set_proc` fails (e.g., permission denied, invalid label).
                 Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr = mac_from_text(label_text)
    try:
        ret = libmac.mac_set_proc(mac_ptr)
        if ret != 0:
            err = ffi.errno
            raise OSError(err, os.strerror(err), f"Failed to set process MAC label to '{label_text}'")
    finally:
        mac_free(mac_ptr) # Always free the mac_t obtained from mac_from_text

def mac_get_file(path):
    """
    Gets the MAC label of a file or directory.

    Args:
        path (str): The path to the file or directory.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the file/directory.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_file_label`
                 or `mac_get_file` fails. Includes the OS error number and message.
        FileNotFoundError: If the specified path does not exist.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr_ptr = ffi.new("mac_t *")
    # Use mac_prepare_file_label for default initialization
    ret = libmac.mac_prepare_file_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to prepare file MAC label for path '{path}'")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_file(_encode_string(path), mac_ptr)
        if ret != 0:
            err = ffi.errno
            # Specifically check for ENOENT before raising a generic OSError
            if err == errno.ENOENT:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno), path)
            raise OSError(err, os.strerror(err), f"Failed to get MAC label for path '{path}'")
        return mac_ptr # Return the mac_t structure, user must free it
    except Exception:
        mac_free(mac_ptr) # Clean up if error
        raise

def mac_set_file(path, label_text):
    """
    Sets the MAC label of a file or directory.

    Args:
        path (str): The path to the file or directory.
        label_text (str): The text representation of the MAC label to set.

    Raises:
        OSError: If libmac is not available, or if `mac_from_text` or
                 `mac_set_file` fails (e.g., permission denied, invalid label).
                 Includes the OS error number and message.
        FileNotFoundError: If the specified path does not exist.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr = mac_from_text(label_text)
    try:
        ret = libmac.mac_set_file(_encode_string(path), mac_ptr)
        if ret != 0:
            err = ffi.errno
            if err == errno.ENOENT:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno), path)
            raise OSError(err, os.strerror(err), f"Failed to set MAC label for path '{path}' to '{label_text}'")
    finally:
        mac_free(mac_ptr)

# Implementation of remaining wrappers

def mac_get_fd(fd):
    """
    Gets the MAC label of an open file descriptor.

    Note: The preparation of the `mac_t` label (using `mac_prepare_file_label`)
    is a guess. A more specific `mac_prepare_fd_label` or similar might be
    appropriate if available or required by the active MAC policies.

    Args:
        fd (int): The file descriptor.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the file descriptor.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_file_label`
                 or `mac_get_fd` fails. Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr_ptr = ffi.new("mac_t *")
    # TODO: Verify if mac_prepare_file_label is appropriate for fds,
    # or if a different/no preparation is needed.
    ret = libmac.mac_prepare_file_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to prepare MAC label for fd {fd}")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_fd(fd, mac_ptr)
        if ret != 0:
            err = ffi.errno
            raise OSError(err, os.strerror(err), f"Failed to get MAC label for fd {fd}")
        return mac_ptr # Return the mac_t structure, user must free it
    except Exception:
        mac_free(mac_ptr)
        raise

def mac_set_fd(fd, label_text):
    """
    Sets the MAC label of an open file descriptor.

    Args:
        fd (int): The file descriptor.
        label_text (str): The text representation of the MAC label to set.

    Raises:
        OSError: If libmac is not available, or if `mac_from_text` or
                 `mac_set_fd` fails (e.g., permission denied, invalid label).
                 Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr = mac_from_text(label_text)
    try:
        ret = libmac.mac_set_fd(fd, mac_ptr)
        if ret != 0:
            err = ffi.errno
            raise OSError(err, os.strerror(err), f"Failed to set MAC label for fd {fd} to '{label_text}'")
    finally:
        mac_free(mac_ptr)

def mac_get_link(path):
    """
    Gets the MAC label of a symbolic link itself (not the target).

    Args:
        path (str): The path to the symbolic link.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the symbolic link.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_file_label`
                 or `mac_get_link` fails. Includes the OS error number and message.
        FileNotFoundError: If the specified path does not exist or is not a link.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr_ptr = ffi.new("mac_t *")
    # Assuming symlinks use file-like labels for preparation
    ret = libmac.mac_prepare_file_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to prepare MAC label for link '{path}'")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_link(_encode_string(path), mac_ptr)
        if ret != 0:
            err = ffi.errno
            if err == errno.ENOENT:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno), path)
            raise OSError(err, os.strerror(err), f"Failed to get MAC label for link '{path}'")
        return mac_ptr # User must free
    except Exception:
        mac_free(mac_ptr)
        raise

def mac_set_link(path, label_text):
    """
    Sets the MAC label of a symbolic link itself (not the target).

    Args:
        path (str): The path to the symbolic link.
        label_text (str): The text representation of the MAC label to set.

    Raises:
        OSError: If libmac is not available, or if `mac_from_text` or
                 `mac_set_link` fails (e.g., permission denied, invalid label).
                 Includes the OS error number and message.
        FileNotFoundError: If the specified path does not exist or is not a link.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr = mac_from_text(label_text)
    try:
        ret = libmac.mac_set_link(_encode_string(path), mac_ptr)
        if ret != 0:
            err = ffi.errno
            if err == errno.ENOENT:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno), path)
            raise OSError(err, os.strerror(err), f"Failed to set MAC label for link '{path}' to '{label_text}'")
    finally:
        mac_free(mac_ptr)

def mac_get_peer(fd):
    """
    Gets the MAC label of the peer connected to a socket.

    Note: The preparation of the `mac_t` label (using `mac_prepare_ifnet_label`)
    is a guess. A more specific `mac_prepare_socket_label` or similar might be
    appropriate if available or required by the active MAC policies.

    Args:
        fd (int): The file descriptor of the socket.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the peer.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_ifnet_label`
                 or `mac_get_peer` fails (e.g., fd is not a socket,
                 socket not connected, operation not supported by policy).
                 Includes the OS error number and message.
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr_ptr = ffi.new("mac_t *")
    # TODO: Verify if mac_prepare_ifnet_label is appropriate for sockets,
    # or if a different/no preparation is needed.
    ret = libmac.mac_prepare_ifnet_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to prepare MAC label for peer of fd {fd}")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_peer(fd, mac_ptr)
        if ret != 0:
            err = ffi.errno
            # Common errors for sockets: EOPNOTSUPP if not a socket, ENOTCONN if not connected
            raise OSError(err, os.strerror(err), f"Failed to get MAC label for peer of fd {fd}")
        return mac_ptr # User must free
    except Exception:
        mac_free(mac_ptr)
        raise

def mac_get_pid(pid):
    """
    Gets the MAC label of a process specified by its PID.

    Args:
        pid (int): The Process ID.

    Returns:
        cdata 'mac_t': Pointer to the MAC label structure of the specified process.
                       This structure must be freed by calling `mac_free()`.

    Raises:
        OSError: If libmac is not available, or if `mac_prepare_process_label`
                 or `mac_get_pid` fails. Includes the OS error number and message.
        ProcessLookupError: If the specified PID does not exist (ESRCH).
    """
    if not libmac:
        raise OSError(errno.ENOSYS, "MAC framework not available")

    mac_ptr_ptr = ffi.new("mac_t *")
    # Processes use process-specific label preparation
    ret = libmac.mac_prepare_process_label(mac_ptr_ptr)
    if ret != 0:
        err = ffi.errno
        raise OSError(err, os.strerror(err), f"Failed to prepare MAC label for PID {pid}")

    mac_ptr = mac_ptr_ptr[0]

    try:
        ret = libmac.mac_get_pid(pid, mac_ptr)
        if ret != 0:
            err = ffi.errno
            # ESRCH if PID does not exist
            if err == errno.ESRCH:
                 raise ProcessLookupError(errno.ESRCH, os.strerror(errno), f"PID {pid} not found") # Corrected
            raise OSError(err, os.strerror(err), f"Failed to get MAC label for PID {pid}")
        return mac_ptr # User must free
    except Exception:
        mac_free(mac_ptr)
        raise

# TODO: Implement mapping from Linux capabilities to MAC labels/policies.
# This is a major design task. It involves:
#   - Identifying relevant MAC policies (e.g., mac_bsdextended, mac_portacl,
#     mac_biba, mac_mls).
#   - Determining how to represent Linux capabilities using these policies.
#   - Designing a configuration interface for users to map capabilities
#     to specific policy behaviors or labels.
# TODO: Investigate if more specific mac_prepare_*_label functions are needed
# for file descriptors and sockets, or if the current usage of
# mac_prepare_file_label and mac_prepare_ifnet_label is sufficiently robust
# across common MAC policies. (See mac_get_fd and mac_get_peer).
# TODO: Add more comprehensive error checking and potentially custom exceptions
# for common MAC framework errors beyond basic OSErrors.
# TODO: Consider adding wrappers for mac_prepare() or mac_prepare_type() if
# a more generic label preparation mechanism is required.

# Example of how a capability might be conceptualized (very simplified):
# LINUX_CAP_NET_BIND_SERVICE -> Check/Set mac_portacl rule or a specific label
# mac_portacl for network port binding, or label-based policies like mac_biba/mac_mls
# for integrity/confidentiality levels.

# Example of how a capability might be conceptualized (very simplified):
# LINUX_CAP_NET_BIND_SERVICE -> Check/Set mac_portacl rule or a specific label
#                                 on a relevant MAC policy (e.g. biba/mls) that
#                                 governs network operations.

# The mapping itself is complex because MAC is policy-driven and Linux capabilities
# are a fixed set of privileges. A direct one-to-one mapping is unlikely.
# We might need a configuration layer where users specify how oslo_privsep
# should interpret certain MAC policies/labels as "capabilities".

if __name__ == '__main__':
    # Example Usage (for testing purposes, assumes FreeBSD environment)
    # This part will likely fail if not on a MAC-enabled FreeBSD system.
    if libmac and libc: # Ensure both libmac and libc (for free) are loaded
        print("MAC Framework and libc appear to be available.")

        # Test process label
        try:
            print("Testing process MAC labels...")
            proc_label_obj = mac_get_proc()
            proc_label_text = mac_to_text(proc_label_obj)
            print(f"Current process label: {proc_label_text}")
            mac_free(proc_label_obj) # Important: free the mac_t object

            # Test setting process label (requires privileges)
            # This will likely fail if not run as root or with specific MAC privileges
            # For testing, one might try to set it to its current value if allowed.
            # Or, if a specific policy allows unprivileged changes within a range.
            # mac_set_proc(proc_label_text)
            # print(f"Successfully set process label to: {proc_label_text}")

        except OSError as e:
            print(f"Error with process MAC labels: {e}")
        except Exception as e:
            print(f"An unexpected error occurred with process MAC labels: {e}")

        # Test file label (e.g., on /tmp)
        TEST_FILE_PATH = "/tmp/mac_test_file.txt"
        try:
            print(f"\nTesting file MAC labels on '{TEST_FILE_PATH}'...")
            # Create a dummy file for testing
            with open(TEST_FILE_PATH, "w") as f:
                f.write("test")

            file_label_obj = mac_get_file(TEST_FILE_PATH)
            file_label_text = mac_to_text(file_label_obj)
            print(f"Label of '{TEST_FILE_PATH}': {file_label_text}")
            mac_free(file_label_obj)

            # Test setting file label (requires privileges)
            # Example: try to set it to 'biba/low' if mac_biba is loaded & configured
            # This also depends on the MAC policies active on the system.
            # mac_set_file(TEST_FILE_PATH, "biba/low")
            # print(f"Successfully set label of '{TEST_FILE_PATH}' to 'biba/low'")
            # Re-get to verify
            # file_label_obj_after_set = mac_get_file(TEST_FILE_PATH)
            # print(f"New label of '{TEST_FILE_PATH}': {mac_to_text(file_label_obj_after_set)}")
            # mac_free(file_label_obj_after_set)

        except FileNotFoundError:
            print(f"File not found: {TEST_FILE_PATH}")
        except OSError as e:
            print(f"Error with file MAC labels for '{TEST_FILE_PATH}': {e}")
        except Exception as e:
            print(f"An unexpected error occurred with file MAC labels: {e}")
        finally:
            if os.path.exists(TEST_FILE_PATH):
                os.remove(TEST_FILE_PATH)

        # Example for mac_get_pid (testing with current process PID)
        try:
            current_pid = os.getpid()
            print(f"\nTesting mac_get_pid for current process (PID: {current_pid})...")
            pid_label_obj = mac_get_pid(current_pid)
            pid_label_text = mac_to_text(pid_label_obj)
            print(f"Label of PID {current_pid}: {pid_label_text}")
            mac_free(pid_label_obj)
        except ProcessLookupError as e:
            print(f"Error looking up process: {e}")
        except OSError as e:
            print(f"Error with PID MAC labels for PID {current_pid}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred with PID MAC labels: {e}")

    else:
        if not libmac:
            print("MAC Framework (libmac) not loaded. Skipping examples.")
        if not libc:
            print("Standard C library (libc) not loaded. Memory management for mac_to_text might fail. Skipping examples.")
