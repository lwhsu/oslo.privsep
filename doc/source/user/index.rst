=======
 Usage
=======

oslo.privsep lets you define in your code specific functions that will run
in predefined privilege contexts. This lets you run functions with more (or
less) privileges than the rest of the code. Privsep functions live in a
specific ``privsep`` submodule (for example, ``nova.privsep`` for nova).

Defining a context
==================

Contexts are defined in the ``privsep/__init__.py`` file. For example, this
defines a sys_admin_pctxt with ``CAP_CHOWN``, ``CAP_DAC_OVERRIDE``,
``CAP_DAC_READ_SEARCH``, ``CAP_FOWNER``, ``CAP_NET_ADMIN``, and
``CAP_SYS_ADMIN`` rights (equivalent to ``sudo`` rights)::

  from oslo_privsep import capabilities
  from oslo_privsep import priv_context

  sys_admin_pctxt = priv_context.PrivContext(
      'nova',
      cfg_section='nova_sys_admin',
      pypath=__name__ + '.sys_admin_pctxt',
      capabilities=[capabilities.CAP_CHOWN,
                    capabilities.CAP_DAC_OVERRIDE,
                    capabilities.CAP_DAC_READ_SEARCH,
                    capabilities.CAP_FOWNER,
                    capabilities.CAP_NET_ADMIN,
                    capabilities.CAP_SYS_ADMIN],
  )

Defining a context with timeout
-------------------------------

It is possible to initialize PrivContext with timeout::

  from oslo_privsep import capabilities
  from oslo_privsep import priv_context

  dhcp_release_cmd = priv_context.PrivContext(
      __name__,
      cfg_section='privsep_dhcp_release',
      pypath=__name__ + '.dhcp_release_cmd',
      capabilities=[caps.CAP_SYS_ADMIN,
                    caps.CAP_NET_ADMIN],
      timeout=5
  )

``PrivsepTimeout`` is raised if timeout is reached.

.. warning::

   The daemon (the root process) task won't stop when timeout
   is reached. That means we'll have less available threads if the related
   thread never finishes.

Defining a privileged function
==============================

Functions are defined in files under the ``privsep/`` subdirectory, for
example in a ``privsep/motd.py`` file for functions touching the MOTD file.
They make use of a decorator pointing to the context we defined above::

  import nova.privsep

  @nova.privsep.sys_admin_pctxt.entrypoint
  def update_motd(message):
      with open('/etc/motd', 'w') as f:
          f.write(message)

Privileged functions must be as simple, specialized and narrow as possible,
so as to prevent further escalation. In this example, ``update_motd(message)``
is narrow: it only allows the service to overwrite the MOTD file. If a more
generic ``update_file(filename, content)`` was created, it could be used to
overwrite any file in the filesystem, allowing easy escalation to root
rights. That would defeat the whole purpose of oslo.privsep.

Defining a privileged function with timeout
-------------------------------------------

It is possible to use ``entrypoint_with_timeout`` decorator::

  from oslo_privsep import daemon

  from neutron import privileged

  @privileged.default.entrypoint_with_timeout(timeout=5)
  def get_link_devices(namespace, **kwargs):
      try:
          with get_iproute(namespace) as ip:
              return make_serializable(ip.get_links(**kwargs))
      except OSError as e:
          if e.errno == errno.ENOENT:
              raise NetworkNamespaceNotFound(netns_name=namespace)
          raise
      except daemon.FailedToDropPrivileges:
          raise
      except daemon.PrivsepTimeout:
          raise

``PrivsepTimeout`` is raised if timeout is reached.

.. warning::

   The daemon (the root process) task won't stop when timeout
   is reached. That means we'll have less available threads if the related
   thread never finishes.

Using a privileged function
===========================

To use the privileged function in the regular code, you can just call it::

  import nova.privsep.motd
  ...

  nova.privsep.motd.update_motd('This node is currently idle')

It is better to import the complete path (``import nova.privsep.motd``) rather
than the motd name (``from nova.privsep import motd``) so that it is easier to
spot that the function runs in a different privileged context.

For more details, you can read the following blog post:

* `How to make a privileged call with oslo privsep`_

.. _How to make a privileged call with oslo privsep: https://www.madebymikal.com/how-to-make-a-privileged-call-with-oslo-privsep/


Converting from rootwrap to privsep
===================================

oslo.rootwrap is a precursor of oslo.privsep to allow code to run commands
under sudo if they match a predefined filter. For example, you could define
a filter that would allow you to run chmod as root using the following
filter::

  chmod: CommandFilter, chmod, root

Beyond the bad performance of calling full commands in order to accomplish
simple tasks, rootwrap also led to bad security: it was difficult to filter
commands in a way that would not easily allow privilege escalation.

Replacing rootwrap filters with privsep functions is easy. The chmod filter
above can be replaced with a function that calls ``os.chmod()``. However a
straight 1:1 filter:function replacement generally results in functions that
are still too broad for good security. It is better to replace each chmod
rootwrap *call* with a narrow privsep function that will limit it to specific
files.

Sometimes it is necessary to refactor the calling code: the rootwrap design
discouraged the creation of new filters and therefore often resulted in the
creation of overly-broad calling functions.

As an example, this `patch series`_ is work-in-progress to transition Nova
from rootwrap to privsep.

For more details, you can read the following blog post:

* `Adding oslo privsep to a new project, a worked example`_

.. _patch series: https://review.openstack.org/#/q/project:openstack/nova+branch:master+topic:my-own-personal-alternative-universe

.. _Adding oslo privsep to a new project, a worked example: https://www.madebymikal.com/adding-oslo-privsep-to-a-new-project-a-worked-example/


FreeBSD MAC Framework Support
=============================

oslo.privsep provides support for leveraging the FreeBSD Mandatory Access
Control (MAC) framework. This allows the privsep daemon to run under a
specific MAC label, enhancing security by utilizing FreeBSD's native MAC
capabilities. This is an alternative to the traditional ``fork`` or
``rootwrap`` methods for privilege separation.

Using the MAC Method
--------------------

To use the MAC framework backend, you need to specify `Method.MAC` when
starting the `PrivContext`.

.. code-block:: python

    from oslo_privsep import priv_context

    # Assuming 'my_context' is an instance of PrivContext
    my_context.start(method=priv_context.Method.MAC)

This instructs oslo.privsep to use the `MACClientChannel` and `MACDaemon`,
which are designed to work with the FreeBSD MAC framework.

Configuration
-------------

A new configuration option is available for contexts that will use the
`Method.MAC`:

`mac_daemon_label`
  Sets the MAC label that the `privsep-helper` daemon will attempt to apply to
  itself.
  * **Type**: String
  * **Default**: `None` (the daemon runs with its default inherited label)
  * **Example**: ``biba/low``, ``mls/high(low-high)``, ``seeplab/off``
  * **Format**: The exact format of the label string is dependent on the
    specific MAC policies (e.g., `mac_biba`, `mac_mls`, `mac_seeplabel`)
    active and configured on the FreeBSD system.

This option should be set in the configuration section corresponding to your
`PrivContext`. For example, if your context's `cfg_section` is `privsep_my_service`:

.. code-block:: ini

    [privsep_my_service]
    # ... other options like user, group ...
    mac_daemon_label = biba/low

System Configuration (FreeBSD)
------------------------------

To effectively use this backend:

1.  The FreeBSD system must have the MAC framework enabled.
2.  Relevant MAC policies (e.g., `mac_biba`, `mac_mls`, `mac_portacl`, etc.)
    must be loaded and configured in the FreeBSD kernel and system settings.
    Refer to the FreeBSD Handbook and `mac(4)`, `maclabel(7)`, and specific
    policy man pages (e.g., `mac_biba(4)`) for details.
3.  The user that `privsep-helper` runs as (either root or a user specified
    via `sudo` in `helper_command`) must have the necessary permissions within
    the MAC policy framework to transition to or operate under the specified
    `mac_daemon_label`.

Capability Mapping Note
-----------------------

The current implementation of the MAC backend focuses on setting an overall
MAC label for the entire `privsep-helper` daemon process. This ensures the
daemon operates within a security context defined by the chosen MAC policy
and label.

Direct mapping of Linux-style capabilities (e.g., `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
to granular MAC policy enforcement (e.g., allowing only specific network
operations based on a label) is **not yet implemented**. Such fine-grained
control would require a more complex mapping layer and could be a
future enhancement. The primary benefit of the current MAC support is the
ability to confine the privsep daemon using FreeBSD's robust, system-wide
MAC policies.
