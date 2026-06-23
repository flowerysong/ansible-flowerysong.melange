#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2012-2013, Timothy Appnel <tim@appnel.com>
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r'''
---
module: synchronize
short_description: A wrapper around rsync to make common tasks in your playbooks quick and easy
description:
    - M(flowerysong.melange.synchronize) is a wrapper around C(rsync) to make
      common tasks in your playbooks quick and easy and the lives of module
      authors slow and frustrating.
    - You could just use the M(ansible.builtin.command) action to call C(rsync)
      yourself, but that can involve a fair number of boilerplate options and
      host facts, with far fewer opportunities for confusion and annoyance.
    - This module is not intended to provide access to the full power of
      C(rsync), but does make the most common invocations less verbose.
      You may still need to call C(rsync) directly depending on your use case
      and tolerance for tomfoolery.
version_added: "1.2.0"
options:
  src:
    description:
      - Path on the source host that will be synchronized to the destination.
      - The path can be absolute or relative.
    type: path
    required: true
  dest:
    description:
      - Path on the destination host that will be synchronized from the source.
      - The path can be absolute or relative.
    type: path
    required: true
  dest_port:
    description:
      - Port number for ssh on the destination host.
      - This parameter defaults to the value of C(ansible_port), the
        C(remote_port) config setting, or the value from ssh client
        configuration if none of the former have been set.
    type: int
  mode:
    description:
      - Specify the direction of the synchronization.
      - In V(push) mode the localhost or delegate is the source.
      - In V(pull) mode the remote host in context is the source.
    type: str
    choices: [ pull, push ]
    default: push
  archive:
    description:
      - Mirrors the rsync archive flag, enables recursive, links, perms, times, owner, group flags, and C(-D).
    type: bool
    default: true
  checksum:
    description:
      - Skip based on checksum, rather than mod-time & size.
      - Note that O(archive) is still enabled by default—O(checksum) does
        not affect it.
    type: bool
    default: false
  compress:
    description:
      - Compress file data during the transfer.
      - In most cases, leave this enabled unless it causes problems.
    type: bool
    default: true
  existing_only:
    description:
      - Skip creating new files on receiver.
    type: bool
    default: false
  delete:
    description:
      - Delete files in O(dest) that do not exist (after transfer, not before)
        in the O(src) path.
      - This option requires O(recursive=true).
      - This option ignores excluded files and behaves like the rsync opt
        C(--delete-after).
    type: bool
    default: false
  dirs:
    description:
      - Transfer directories without recursing.
    type: bool
    default: false
  recursive:
    description:
      - Recurse into directories.
      - This parameter defaults to the value of O(archive).
    type: bool
  links:
    description:
      - Copy symlinks as symlinks.
      - This parameter defaults to the value of O(archive).
    type: bool
  copy_links:
    description:
      - Copy symlinks as the item that they point to (the referent) is copied,
        rather than the symlink.
    type: bool
    default: false
  perms:
    description:
      - Preserve permissions.
      - This parameter defaults to the value of O(archive).
    type: bool
  times:
    description:
      - Preserve modification times.
      - This parameter defaults to the value of O(archive).
    type: bool
  owner:
    description:
      - Preserve owner (super user only).
      - This parameter defaults to the value of O(archive).
    type: bool
  group:
    description:
      - Preserve group.
      - This parameter defaults to the value of O(archive).
    type: bool
  rsync_path:
    description:
      - Specify the rsync command to run on the remote host.
      - See C(--rsync-path) on the rsync man page.
      - To specify the rsync command to run on the local host, you need to set
        the variable C(ansible_rsync_path).
    type: str
  rsync_timeout:
    description:
      - Specify a C(--timeout) for the rsync command in seconds.
    type: int
    default: 0
  set_remote_user:
    description:
      - Add C(user@) to the remote paths.
      - If you have a custom ssh config to define the remote user for a host
        that does not match the inventory user, you should set this parameter
        to V(false).
    type: bool
    default: true
  use_ssh_args:
    description:
      - Enables the use of all SSH connection configuration options, like
        C(ansible_ssh_args), C(ansible_ssh_common_args), and C(ansible_ssh_extra_args).
    type: bool
    default: false
  ssh_connection_multiplexing:
    description:
      - SSH connection multiplexing for rsync is disabled by default to prevent
        misconfigured C(ControlSockets) from resulting in failed SSH
        connections. This is accomplished by setting the SSH C(ControlSocket)
        to C(none).
      - Enable this option to allow multiplexing and reduce SSH connection
        overhead.
    type: bool
    default: false
  rsync_opts:
    description:
      - Specify additional C(rsync) options by passing in an array.
      - Note that an empty string in O(rsync_opts) will end up transferring the
        current working directory.
    type: list
    default:
    elements: str
  partial:
    description:
      - Tells rsync to keep partial files, which can make a subsequent transfer
        of the rest of the file much faster.
    type: bool
    default: false
  verify_host:
    description:
      - Verify destination host key.
    type: bool
    default: false
  private_key:
    description:
      - Specify the private key to use for SSH-based rsync connections (e.g.
        V(~/.ssh/id_rsa)).
    type: path
  link_dest:
    description:
      - Add a destination to hard link against during the transfer.
    type: list
    default:
    elements: path
  delay_updates:
    description:
      - This option puts a temporary copy of each updated file into a
        holding directory until the end of the transfer, at which time all the
        files are renamed into place in rapid succession.
    type: bool
    default: true

notes:
   - C(rsync) must be installed on both the local and remote host.
   - For the M(flowerysong.melange.synchronize) module, the "local host" is the
     host I(the synchronize task originates on), and the "destination host" is
     the host I(synchronize is connecting to).
   - The "local host" can be changed to a different host by using
     C(delegate_to). This enables copying between two remote hosts or entirely
     on one remote machine.
   - The user and permissions for O(src) are those of the user running the
     Ansible task on the local host (or the C(remote_user) for a delegated host
     when C(delegate_to) is used).
   - The user and permissions for O(dest) are those of the C(remote_user) on
     the destination host, or C(become_user) if privilege escalation is used.
   - M(flowerysong.melange.synchronize) is limited to elevating permissions
     via passwordless sudo. This is because C(rsync) itself is connecting to
     the remote machine and C(rsync) doesn't provide a way to handle privilege
     escalation that requires credentials.
   - Currently there are only a few connection types which support
     M(flowerysong.melange.synchronize) (P(ansible.builtin.ssh#connection),
     P(ansible.builtin.local#connection), and
     P(community.docker.docker#connection). Note that the connection for these
     must not need a password as C(rsync) is making the connection and
     does not have a way to pass a password to the connection.
   - Expect that O(dest=~/x) will be V(~<remote_user>/x) even if using privilege escalation.
   - To exclude files and directories from being synchronized, you can add
     C(.rsync-filter) files to the source directory.
   - The C(rsync) daemon must be up and running with correct permissions when
     using the rsync protocol in O(src) or O(dest).
   - O(link_dest) is subject to the same limitations as the underlying C(rsync)
     daemon. Hard links are only preserved if the relative subtrees of the
     source and destination are the same. Attempts to hardlink into a directory
     that is a subdirectory of the source will be prevented.
seealso:
- module: ansible.builtin.copy
- module: community.windows.win_robocopy
author:
- Timothy Appnel (@tima)
'''

EXAMPLES = r'''
- name: Synchronization of src on the control machine to dest on the remote hosts
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path

- name: Synchronization using rsync protocol (push)
  flowerysong.melange.synchronize:
    src: some/relative/path/
    dest: rsync://somehost.com/path/

- name: Synchronization using rsync protocol (pull)
  flowerysong.melange.synchronize:
    mode: pull
    src: rsync://somehost.com/path/
    dest: /some/absolute/path/

- name: Synchronization using rsync protocol on delegate host (push)
  flowerysong.melange.synchronize:
    src: /some/absolute/path/
    dest: rsync://somehost.com/path/
  delegate_to: delegate.host

- name: Synchronization using rsync protocol on delegate host (pull)
  flowerysong.melange.synchronize:
    mode: pull
    src: rsync://somehost.com/path/
    dest: /some/absolute/path/
  delegate_to: delegate.host

- name: Synchronization without any --archive options enabled
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    archive: false

- name: Synchronization with --archive options enabled except for --recursive
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    recursive: false

- name: Synchronization with --archive options enabled except for --times, with --checksum option enabled
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    checksum: true
    times: false

- name: Synchronization without --archive options enabled except use --links
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    archive: false
    links: true

- name: Synchronization of two paths both on the control machine
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
  delegate_to: localhost

- name: Synchronization of src on the inventory host to the dest on the localhost in pull mode
  flowerysong.melange.synchronize:
    mode: pull
    src: some/relative/path
    dest: /some/absolute/path

- name: Synchronization of src on delegate host to dest on the current inventory host.
  flowerysong.melange.synchronize:
    src: /first/absolute/path
    dest: /second/absolute/path
  delegate_to: delegate.host

- name: Synchronize two directories on one remote host.
  flowerysong.melange.synchronize:
    src: /first/absolute/path
    dest: /second/absolute/path
  delegate_to: "{{ inventory_hostname }}"

- name: Synchronize and delete files in dest on the remote host that are not found in src of localhost.
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    delete: true
    recursive: true

# This specific command is granted su privileges on the destination
- name: Synchronize using an alternate rsync command
  flowerysong.melange.synchronize:
    src: some/relative/path
    dest: /some/absolute/path
    rsync_path: su -c rsync

# Example .rsync-filter file in the source directory
# - var       # exclude any path whose last part is 'var'
# - /var      # exclude any path starting with 'var' starting at the source directory
# + /var/conf # include /var/conf even though it was previously excluded

- name: Synchronize passing in extra rsync options
  flowerysong.melange.synchronize:
    src: /tmp/helloworld
    dest: /var/www/helloworld
    rsync_opts:
      - "--no-motd"
      - "--exclude=.git"

# Hardlink files if they didn't change
- name: Use hardlinks when synchronizing filesystems
  flowerysong.melange.synchronize:
    src: /tmp/path_a/foo.txt
    dest: /tmp/path_b/foo.txt
    link_dest: /tmp/path_a/

# Specify the rsync binary to use on remote host and on local host
- hosts: groupofhosts
  vars:
    ansible_rsync_path: /usr/gnu/bin/rsync

  tasks:
    - name: copy /tmp/localpath/ to remote location /tmp/remotepath
      flowerysong.melange.synchronize:
        src: /tmp/localpath/
        dest: /tmp/remotepath
        rsync_path: /usr/gnu/bin/rsync
'''


import os
import errno

from shlex import quote as shlex_quote

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_native


client_addr = None


def substitute_controller(path):
    global client_addr
    if not client_addr:
        ssh_env_string = os.environ.get('SSH_CLIENT', None)
        try:
            client_addr, junk = ssh_env_string.split(None, 1)
        except AttributeError:
            ssh_env_string = os.environ.get('SSH_CONNECTION', None)
            try:
                client_addr, junk = ssh_env_string.split(None, 1)
            except AttributeError:
                pass
        if not client_addr:
            raise ValueError

    if path.startswith('localhost:'):
        path = path.replace('localhost', client_addr, 1)
    return path


def is_rsh_needed(source, dest):
    if source.startswith('rsync://') or dest.startswith('rsync://'):
        return False
    if ':' in source or ':' in dest:
        return True
    return False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(type='path', required=True),
            dest=dict(type='path', required=True),
            dest_port=dict(type='int'),
            delete=dict(type='bool', default=False),
            private_key=dict(type='path'),
            rsync_path=dict(type='str'),
            _local_rsync_path=dict(type='path', default='rsync'),
            _local_rsync_password=dict(type='str', no_log=True),
            _substitute_controller=dict(type='bool', default=False),
            archive=dict(type='bool', default=True),
            checksum=dict(type='bool', default=False),
            compress=dict(type='bool', default=True),
            existing_only=dict(type='bool', default=False),
            dirs=dict(type='bool', default=False),
            recursive=dict(type='bool'),
            links=dict(type='bool'),
            copy_links=dict(type='bool', default=False),
            perms=dict(type='bool'),
            times=dict(type='bool'),
            owner=dict(type='bool'),
            group=dict(type='bool'),
            set_remote_user=dict(type='bool', default=True),
            rsync_timeout=dict(type='int', default=0),
            rsync_opts=dict(type='list', default=[], elements='str'),
            ssh_args=dict(type='str'),
            ssh_connection_multiplexing=dict(type='bool', default=False),
            partial=dict(type='bool', default=False),
            verify_host=dict(type='bool', default=False),
            delay_updates=dict(type='bool', default=True),
            mode=dict(type='str', default='push', choices=['pull', 'push']),
            link_dest=dict(type='list', elements='path'),
        ),
        supports_check_mode=True,
    )

    if module.params['_substitute_controller']:
        try:
            source = substitute_controller(module.params['src'])
            dest = substitute_controller(module.params['dest'])
        except ValueError:
            module.fail_json(msg='Could not determine controller hostname for rsync to send to')
    else:
        source = module.params['src']
        dest = module.params['dest']
    dest_port = module.params['dest_port']
    delete = module.params['delete']
    private_key = module.params['private_key']
    rsync_path = module.params['rsync_path']
    rsync = module.params.get('_local_rsync_path', 'rsync')
    rsync_password = module.params.get('_local_rsync_password')
    rsync_timeout = module.params.get('rsync_timeout', 'rsync_timeout')
    archive = module.params['archive']
    checksum = module.params['checksum']
    compress = module.params['compress']
    existing_only = module.params['existing_only']
    dirs = module.params['dirs']
    partial = module.params['partial']
    # the default of these params depends on the value of archive
    recursive = module.params['recursive']
    links = module.params['links']
    copy_links = module.params['copy_links']
    perms = module.params['perms']
    times = module.params['times']
    owner = module.params['owner']
    group = module.params['group']
    rsync_opts = module.params['rsync_opts']
    ssh_args = module.params['ssh_args']
    ssh_connection_multiplexing = module.params['ssh_connection_multiplexing']
    verify_host = module.params['verify_host']
    link_dest = module.params['link_dest']
    delay_updates = module.params['delay_updates']

    if '/' not in rsync:
        rsync = module.get_bin_path(rsync, required=True)

    cmd = [rsync]
    _sshpass_pipe = None
    if rsync_password:
        try:
            module.run_command(["sshpass"])
        except OSError:
            module.fail_json(
                msg="to use rsync connection with passwords, you must install the sshpass program"
            )
        _sshpass_pipe = os.pipe()
        cmd = ['sshpass', '-d' + to_native(_sshpass_pipe[0], errors='surrogate_or_strict')] + cmd
    if delay_updates:
        cmd.append('--delay-updates')
        cmd.append('-F')
    if compress:
        cmd.append('--compress')
    if rsync_timeout:
        cmd.append('--timeout=%s' % rsync_timeout)
    if module.check_mode:
        cmd.append('--dry-run')
    if delete:
        cmd.append('--delete-after')
    if existing_only:
        cmd.append('--existing')
    if checksum:
        cmd.append('--checksum')
    if copy_links:
        cmd.append('--copy-links')
    if archive:
        cmd.append('--archive')
        if recursive is False:
            cmd.append('--no-recursive')
        if links is False:
            cmd.append('--no-links')
        if perms is False:
            cmd.append('--no-perms')
        if times is False:
            cmd.append('--no-times')
        if owner is False:
            cmd.append('--no-owner')
        if group is False:
            cmd.append('--no-group')
    else:
        if recursive is True:
            cmd.append('--recursive')
        if links is True:
            cmd.append('--links')
        if perms is True:
            cmd.append('--perms')
        if times is True:
            cmd.append('--times')
        if owner is True:
            cmd.append('--owner')
        if group is True:
            cmd.append('--group')
    if dirs:
        cmd.append('--dirs')

    if source.startswith('rsync://') and dest.startswith('rsync://'):
        module.fail_json(msg='either src or dest must be a localhost', rc=1)

    if is_rsh_needed(source, dest):

        # https://github.com/ansible/ansible/issues/15907
        has_rsh = False
        for rsync_opt in rsync_opts:
            if '--rsh' in rsync_opt:
                has_rsh = True
                break

        # if the user has not supplied an --rsh option go ahead and add ours
        if not has_rsh:
            ssh_cmd = [module.get_bin_path('ssh', required=True)]
            if not ssh_connection_multiplexing:
                ssh_cmd.extend(['-S', 'none'])
            if private_key is not None:
                ssh_cmd.extend(['-i', private_key])
            # If the user specified a port value
            # Note:  The action plugin takes care of setting this to a port from
            # inventory if the user didn't specify an explicit dest_port
            if dest_port is not None:
                ssh_cmd.extend(['-o', 'Port=%s' % dest_port])
            if not verify_host:
                ssh_cmd.extend(['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'])
            ssh_cmd_str = ' '.join(shlex_quote(arg) for arg in ssh_cmd)
            if ssh_args:
                ssh_cmd_str += ' %s' % ssh_args
            cmd.append('--rsh=%s' % shlex_quote(ssh_cmd_str))

    if rsync_path:
        cmd.append('--rsync-path=%s' % shlex_quote(rsync_path))

    if rsync_opts:
        if '' in rsync_opts:
            module.warn('The empty string is present in rsync_opts which will cause rsync to'
                        ' transfer the current working directory. If this is intended, use "."'
                        ' instead to get rid of this warning. If this is unintended, check for'
                        ' problems in your playbook leading to empty string in rsync_opts.')
        cmd.extend(rsync_opts)

    if partial:
        cmd.append('--partial')

    if link_dest:
        cmd.append('-H')
        # verbose required because rsync does not believe that adding a
        # hardlink is actually a change
        cmd.append('-vv')
        for x in link_dest:
            link_path = os.path.abspath(x)
            destination_path = os.path.abspath(os.path.dirname(dest))
            if destination_path.find(link_path) == 0:
                module.fail_json(msg='Hardlinking into a subdirectory of the source would cause recursion. %s and %s' % (destination_path, dest))
            cmd.append('--link-dest=%s' % link_path)

    changed_marker = '<<CHANGED>>'
    cmd.append('--out-format=%s' % shlex_quote(changed_marker + '%i %n%L'))

    cmd.append(shlex_quote(source))
    cmd.append(shlex_quote(dest))
    cmdstr = ' '.join(cmd)

    # If we are using password authentication, write the password into the pipe
    if rsync_password:
        def _write_password_to_pipe(proc):
            os.close(_sshpass_pipe[0])
            try:
                os.write(_sshpass_pipe[1], to_bytes(rsync_password) + b'\n')
            except OSError as exc:
                # Ignore broken pipe errors if the sshpass process has exited.
                if exc.errno != errno.EPIPE or proc.poll() is None:
                    raise

        (rc, out, err) = module.run_command(
            cmdstr, pass_fds=_sshpass_pipe,
            before_communicate_callback=_write_password_to_pipe)
    else:
        (rc, out, err) = module.run_command(cmdstr)

    if rc:
        return module.fail_json(msg=err, rc=rc, cmd=cmdstr)

    if link_dest:
        # a leading period indicates no change
        changed = (changed_marker + '.') not in out
    else:
        changed = changed_marker in out

    out_clean = out.replace(changed_marker, '')
    out_lines = out_clean.split('\n')
    while '' in out_lines:
        out_lines.remove('')
    if module._diff:
        diff = {'prepared': out_clean}
        return module.exit_json(changed=changed, msg=out_clean,
                                rc=rc, cmd=cmdstr, stdout_lines=out_lines,
                                diff=diff)

    return module.exit_json(changed=changed, msg=out_clean,
                            rc=rc, cmd=cmdstr, stdout_lines=out_lines)


if __name__ == '__main__':
    main()
