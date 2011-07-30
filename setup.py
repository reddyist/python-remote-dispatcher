#!/usr/bin/python -tt
# vim: sw=4 ts=4 expandtab ai fileencoding=utf-8
#
# Copyright (C) 2006-2007 Ugandhar Reddy <reddyist@gmail.com>
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
# $ID$

__revision__ = "r"+"$Revision$"[11:-2]

from distutils.core import setup

import glob, os

def debpkgver(changelog = "debian/changelog"):
    return open(changelog).readline().split(' ')[1][1:-1]


setup (name = "python-remote-dispatcher",
    description="remote copy and execute commands",
    version=debpkgver(),
    author="Ugandhar Reddy",
    author_email="reddyist@gmail.com",
    packages=['rdispatcher',],
    license="GPL",
    long_description="Interface for remote authentication, copying and executing commands"
)

# EOF

