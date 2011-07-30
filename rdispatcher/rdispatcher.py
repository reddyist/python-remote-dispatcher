#!/usr/bin/python -tt
# vim: sw=4 ts=4 expandtab ai
#
# Copyright (C) 2008 Ugandhar Reddy <reddyist@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301 USA
#
# $Id$

"""Provides secure copy and command execution on a remote system"""

__all__ = ['RemoteDispatcherException', 'RemoteDispatcher', 
           'SFTPClient']

__revision__ = "r"+"$Revision$"


from os import environ as local_environ
from os import walk as local_walk

from os.path import join as joinpath
from os.path import sep as pathsep

from os.path import expanduser as local_expanduser
from os.path import normpath as local_normpath
from os.path import basename as local_basename
from os.path import getsize as local_getsize
from os.path import dirname as local_dirname
from os.path import isfile as local_isfile
from os.path import isdir as local_isdir
from os.path import exists as local_pathexists

import glob
import stat

import paramiko

from collections import deque

import logging
LOG = logging.getLogger(__name__)



class RemoteDispatcherException(Exception):
    """ Encapsulates sftp exceptions """
    pass


class SFTPClient(paramiko.SFTPClient):
    """Extends the paramiko.SFTPClient to provide methods: exists and isdir"""

    def exists(self, name):
        """Check whether name (file name or directory name) exists on remote
        server.
        
        Arguments:
            name (str) - absolute path to a file or directory name
        
        Returns:
            If name exists then True or False
        """
        try:
            self.stat(name)
            return True
        except IOError:
            return False
        else:
            msg = "Error checking file status for %s on remote host" % (name)
            raise RemoteDispatcherException(msg)

    def isdir(self, name):
        """Return True if name is an existing directory
        
        Arguments:
            name (str) - absolute path to a directory name
            
        Returns:
            True if exists else False
        """
        isdir = False
        if not self.exists(name):
            return isdir
    
        try:
            mode = self.lstat(name).st_mode
        except OSError:
            mode = 0
        
        if stat.S_ISDIR(mode):
            isdir = True
        else:
            isdir = False

        return isdir


class  RemoteDispatcher(object):
    """Provides an interface for secure copy and command execution on a remote
    system. At object instantiation it performs authentication, creates 
    transport object which can used in establishing a session with server. A 
    single session b/w local and remote system can be used in multiple channels
    i.e multiple copies or command execution."""
    
    def __init__(self, host, port=22, username=None, password=None, pkey=None):
        """ Creates a new SSH transport object which can be used in starting a 
        session with remote server. The authentication is done based on password
        or private_key.
        
        Arguments:
            host (str) - host name or ip
            port (int) - (optional) defaults to 22
            username (str) - (optional) defaults to command execution username
            password (str) - (optional) defaults to private_key
            pkey (str) - (optional) private key defaults to ~/.ssh/id_rsa key
        
        Actions:
            * Creates SSH transport object
            * Authenticates remotes based on username and private_key|password
        
        """
        self.host = host
        self.port = port
        self.username = username or local_environ['LOGNAME']
        self.password = password
        self.pkey = None
        self.transport = None
        self.sftp_live = False
        self.sftp = None
        
        # Set to info level
        LOG.setLevel(20)
        
        if pkey:
            pkey_file = local_expanduser(pkey)
        else:
            pkey_file = self.__get_privatekey_file()
        
        if not password and not pkey_file:
            raise RemoteDispatcherException(\
                    "You have not specified a password or key.")
         
        if pkey_file:
            self.__load_private_key(pkey_file)
        
        self.__establish_session()

    def __get_privatekey_file(self):
        """Returns user private key"""
        pkey_file = None
        rsa_key_file = local_expanduser('~%s/.ssh/id_rsa' \
                                            % self.username)
        dsa_key_file = local_expanduser('~%s/.ssh/id_dsa' \
                                            % self.username)
        if local_pathexists(rsa_key_file):
            pkey_file = rsa_key_file
        elif local_pathexists(dsa_key_file):
            pkey_file = dsa_key_file

        return pkey_file

    def __load_private_key(self, pkey_file):
        """Loads the key from key file"""
        try:
            pkey =  paramiko.RSAKey.from_private_key_file(pkey_file)
        except paramiko.SSHException:
            try:
                pkey = paramiko.DSSKey.from_private_key_file(pkey_file)
            except paramiko.SSHException:
                raise RemoteDispatcherException("Invalid private key file: %s"\
                                                % pkey_file)
        self.pkey = pkey
    
    def __establish_session(self):
        """Session will be established b/w local and remote machine"""
        if not self.transport or not self.transport.is_active():
            self.transport = paramiko.Transport((self.host, self.port))
            self.transport.connect(username=self.username, 
                                   password=self.password, 
                                   pkey=self.pkey)
    
    def connect(self):
        """Establish the SFTP connection."""
        if not self.transport.is_active():
            self.close()
            self.__establish_session()
        if not self.sftp_live:
            self.sftp = SFTPClient.from_transport(self.transport)
            self.sftp_live = True
        
    def __construct_remote_paths(self, source, root_dest, remote_directories, 
                                local_remote_files):
        """Computes the directories and files that are to uploaded to remote 
        system.
        
        Arguments:
            source (str) - absolute path to the local source directory
            root_dest (str) - absolute path to the remote destination directory
            remote_directories (list) - list reference where the directories
                                        which has to created will be added
            local_remote_files (list) - list reference where a tuples of
                                        (localfile_path, remotefile_path)
                                        will be added
            root_dest_exists (boolean) - defaults to False; Set to True if dest
                                         exists at remote side

        Returns:
            The return values are append to the reference variables 
            i.e remote_directories and local_remote_files list
        """
        if local_isfile(source):
            root_dest = joinpath(root_dest, local_basename(source))
            local_remote_files.append((source, root_dest))
            return
        
        parent_dest_exists = root_dest_exists = False
        parent_path = root_dest
        
        if self.sftp.isdir(root_dest):
            parent_dest_exists = root_dest_exists = True
        
        for base_dir, _, files in local_walk(source):
            
            dest_dir = local_normpath(joinpath(root_dest,
                              base_dir.replace(source, '').strip(pathsep)))
            
            if root_dest_exists:
                new_parent_path = local_dirname(base_dir)
                if new_parent_path == parent_path and not parent_dest_exists:
                    remote_directories.append(dest_dir)
                else: 
                    parent_path = new_parent_path
                    if not self.sftp.exists(dest_dir):
                        parent_dest_exists = False
                        remote_directories.append(dest_dir)
                    elif not self.sftp.isdir(dest_dir):
                        msg = ''.join(["Copy aborted. Mismatch in file type ",
                                       "Local: '%s' Remote: '%s'" % (base_dir,
                                       dest_dir)])
                        raise RemoteDispatcherException(msg)
                    else:
                        parent_dest_exists = True
            else:
                remote_directories.append(local_normpath(dest_dir))
                
            local_remote_files.extend(\
                [(joinpath(base_dir, fname), \
                  joinpath(dest_dir, fname)) \
                 for fname in files])

    def __get_paths_source_file(self, source, dest):
        """Costructs the the remote directories and files to be created

        Arguments:
            source - local source file path
            dest - remote destionation path
        
        Returns:
            Tuple ([dir1, dir2, ...], 
                   [(local_file_path1, remote_file_path1), 
                    (local_file_path1, remote_file_path2), ...])
        
        """
        remote_directories = deque()
        local_remote_files = deque()
        
        if self.sftp.isdir(dest):
            dest = joinpath(dest, local_basename(source))
        
        local_remote_files.append((source, dest))

        return (remote_directories, local_remote_files)

    def __get_paths_source_dir(self, source, dest):
        """Costructs the the remote directories and files to be created

        Arguments:
            source - local source directory path
            dest - remote destionation path
        
        Returns:
            Tuple ([dir1, dir2, ...], 
                   [(local_file_path1, remote_file_path1), 
                    (local_file_path1, remote_file_path2), ...])
        
        """
        remote_directories = deque()
        local_remote_files = deque()
        
        if self.sftp.isdir(dest):
            dest = joinpath(dest, local_basename(source))
        
        self.__construct_remote_paths(source, dest, remote_directories,
                                      local_remote_files)
        return (remote_directories, local_remote_files)

    def __get_paths_source_pattern(self, source, dest):
        """Costructs the the remote directories and files to be created

        Arguments:
            source - local source pattern
            dest - remote destionation path
        
        Returns:
            Tuple ([dir1, dir2, ...], 
                   [(local_file_path1, remote_file_path1), 
                    (local_file_path1, remote_file_path2), ...])
        
        """
        
        remote_directories = deque()
        local_remote_files = deque()
        root_dest = dest
        
        # Get pattern matching files and directories
        source_list = glob.glob(source)

        if not source_list:
            raise RemoteDispatcherException("File or Directory not found: %s" 
                                            % (source))

        if not self.sftp.isdir(root_dest):
            remote_directories.append(root_dest)
        
        for lfile in source_list:
            # IF lfile is a directory then concatenated the dir-name with
            # remote path.
            if local_isdir(lfile):
                dest = joinpath(root_dest, local_basename(lfile))
            else:
                dest = root_dest

            self.__construct_remote_paths(lfile, dest, remote_directories,
                                         local_remote_files)

        return (remote_directories, local_remote_files)

    def scp(self, source, dest, recursive=False):
        """Copies a file[s] or directories between the local and remote host
        
        Arguments:
            source (str) -  absolute path to the source file or directory 
                            or a pattern
            dest (str) - remote absolute path
            recursive (boolean) - for copying recursively; should be enabled
                                  in case of directory or more than 2 files
                                  i.e pattern matched to be copied
        
        Actions:
            * Get list of directories and files need to uploaded to remote 
              system
            * Create remote directory skeleton
            * Upload the files to respective directories
        
        Returns:
            Exception if errors encountered
        """
        source = local_normpath(source)
        dest = local_normpath(dest)
        
        if local_isdir(source) or len(glob.glob(source)) > 1:
            if not recursive:
                # For copying more than one file recursive flag should be 
                # enabled.
                msg = "Please enable recursive argument to copy recursively"
                LOG.error(msg)
                raise RemoteDispatcherException(msg)
        
        # Establish the secure connection.
        self.connect()
        
        if local_isfile(source):
            (rdirs, lrfiles) = self.__get_paths_source_file(source, dest)
        elif local_isdir(source):
            (rdirs, lrfiles) = self.__get_paths_source_dir(source, dest)
        else:
            # else local_ispattern
            (rdirs, lrfiles) = self.__get_paths_source_pattern(source, dest)
        
        # Create directory skeleton
        for rdir in rdirs:
            try:
                LOG.debug(rdir)
                self.sftp.mkdir(rdir)
            except IOError:
                msg = "Couldn't create dest directory: '%s'" % (rdir)
                LOG.error(msg)
                raise RemoteDispatcherException(msg)
        
        # Upload the files
        for lfile, rfile in lrfiles:
            try:
                LOG.info("%s [%0.3f KB]" % \
                        (local_basename(lfile), 
                         local_getsize(lfile)/float(1024)))
                self.sftp.put(lfile, rfile)
            except IOError:
                msg = "Couldn't copy from local: '%s' to remote: '%s'" \
                      % (lfile, rfile)
                LOG.error(msg)
                raise RemoteDispatcherException(msg)
    
    def execute(self, command):
        """Execute the given commands on a remote machine.
        
        Arguments:
            command (str) - command to be run on remote side

        Returns:
            A tuple (exit_stus, output(stdout|stderr))
        """
        
        # Establish the transport session.
        self.__establish_session()
        
        channel = self.transport.open_session()

        # IF remote process logs the data to stdout and stderr then reading
        # one of them makes the other buffer full as a result the remote 
        # process gets stucked. To avoid this below call combines the stdout
        # and stderr output so that reading one of them is sufficient.
        channel.set_combine_stderr(True)
        
        LOG.info("'%s'" % command)
        channel.exec_command(command)
        output = channel.makefile('rb', -1).readlines()
        if output:
            LOG.info("\n\n%s", ''.join(output))
        
        return (channel.recv_exit_status(), output)
    
    def close(self):
        """Closes the connection and cleans up."""
        # Close SFTP Connection.
        if self.sftp_live:
            self.sftp.close()
            self.sftp_live = False
        if self.transport and self.transport.is_active():
            self.transport.close()

    def __del__(self):
        """Attempt to clean up if not explicitly closed."""
        self.close()

