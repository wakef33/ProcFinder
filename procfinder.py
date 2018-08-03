#!/usr/bin/env python3
'''
ProcFinder parses the procfs in Linux
distributions searching for signs of malware.
'''

import os
import re
import argparse
import subprocess

__version__ = 'ProcFinder 0.4.0'


class Colors():

    RED   = '\033[1;91m'
    GREEN = '\033[1;32m'
    BLUE  = '\033[0;94m'
    WHITE = '\033[0m'

    def warning(self, text):
        print(self.RED + '[-] ' + self.WHITE + text)

    def note(self, text):
        print(self.GREEN + '[+] ' + self.WHITE + text)

    def banner(self, text):
        print(self.BLUE + text + self.WHITE)


class ProcFinder():

    def __init__(self):
        if os.name != 'posix' or os.path.isdir('/proc') == False:
            class_colors = Colors()
            class_colors.warning("ProcFinder is intended to only be ran on a *nix OS with a procfs.")
            raise SystemExit()
        self._pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]


    def __str__(self):
        return "{}".format(self.pids)


    @property
    def pids(self):
        return self._pids


    @pids.setter
    def pids(self, pid_list):
        if isinstance(pid_list, list):
            for i in pid_list:
                if isinstance(i, int):
                    self._pids = pid_list
                else:
                    raise TypeError("PIDs must be in an integer.")
        else:
            raise TypeError("PIDs must be in a list format.")


    def deleted_check(self):
        '''
        Returns a list of PIDs whose binary has
        been deleted from disk.
        '''

        deleted_pids = []
        for pid in self.pids:
            try:
                link = os.readlink('/proc/{}/exe'.format(pid))
                if re.match('.*\(deleted\)$', link):
                    deleted_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return deleted_pids


    def path_check(self):
        '''
        Returns a list of PIDs whose PATH environment
        varibale contains a '.'
        '''

        path_pids = []
        for pid in self.pids:
            try:
                with open('/proc/{}/environ'.format(pid)) as open_env:
                    # Creates a list of all the environment varliables for the process
                    for i in open_env:
                        env_list = i.split('\x00')
                        # Loops through each environment varliable looking for '.' in its PATH
                        for j in env_list:
                            if re.match('^PATH=.*\..*', j):
                                path_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return path_pids


    def promiscuous_check(self):
        '''
        Returns a list of PIDs who are listening
        on an interface promiscuously. Returns
        -1 if /proc/net/packet does not exist.
        '''

        if os.path.isfile('/proc/net/packet') == False:
            return -1
        inode_list = []
        promiscuous_pids = []
        with open('/proc/net/packet') as packet:
            packet_read = packet.readlines()
            for i in packet_read[1::]:
                inode_list.append(i.split()[-1])
        for pid in self.pids:
            try:
                fd_list = [fd for fd in os.listdir('/proc/{}/fd'.format(pid))]
            except OSError:    # proc has already terminated
                continue
            for link_list in fd_list:
                try:
                    fd_link = os.readlink('/proc/{}/fd/{}'.format(pid, link_list))
                    fd_match = list(map(lambda x: re.findall(x, fd_link), inode_list))
                    for i in fd_match:
                        if len(i) > 0:
                            if pid not in promiscuous_pids:
                                promiscuous_pids.append(pid)
                except OSError:    # proc has already terminated
                    continue
        return promiscuous_pids


    def ps_check(self):
        '''
        Returns a list of PIDs whose PID do not match
        with the on disk ps and the PIDs in /proc.
        '''

        ps = subprocess.Popen(['ps', '-eo', 'pid', '--no-headers'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = ps.communicate(timeout=5)[0]
        output_list = output.decode().split('\n')[:-2]
        output_striped = [x.strip(' ') for x in output_list]
        output_int = [int(x) for x in output_list]
        return list(set(output_int).symmetric_difference(self.pids))


    def thread_check(self):
        '''
        Returns a list of PIDs whose process has
        multiple threads and a difference greater
        than 1000 of the smallest and largest thread
        ID. This has a high chance of false positives,
        recommend running multiple times.
        '''

        thread_pids = []
        for pid in self.pids:
            try:
                thread_dirs = [thread for thread in os.listdir('/proc/{}/task'.format(pid))]
                if (int(thread_dirs[-1]) - int(thread_dirs[0])) > 1000:
                    thread_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return thread_pids


    def cwd_check(self):
        '''
        Returns a list of PIDs whose cwd contains
        either /tmp, /dev/shm, or /var/tmp.
        '''

        cwd_pids = []
        for pid in self.pids:
            try:
                open_cwd = os.readlink('/proc/{}/cwd'.format(pid))
                if re.match('^/tmp.*|^/dev/shm.*|^/var/tmp.*', open_cwd):
                    cwd_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return cwd_pids


    def preload_check(self):
        '''
        Returns a list of pids where LD_PRELOAD
        is found as an environment variable.
        '''

        preload_pids = []
        for pid in self.pids:
            try:
                with open('/proc/{}/environ'.format(pid)) as open_env:
                    # Creates a list of all the environment varliables for the process
                    # TODO: replace for loop with env = open_env.read().split('\x00')
                    for i in open_env:
                        env_list = i.split('\x00')
                        # Loops through each environment varliable looking for LD_PRELOAD
                        for j in env_list:
                            if re.match('LD_PRELOAD=.*', j):
                                preload_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return preload_pids


def ko_check():
    '''
    Returns a list of running kernel objects
    that are not found in /lib/modules.
    '''

    # TODO: Needs cleaning up
    ko_list = []
    # Gets current kernel version
    with open('/proc/version') as open_ver:
        version = open_ver.read().split()[2]
    # Creates a list of all .ko files on disk for the running kernel version
    ko_file_list = []
    for root, dirs, files in os.walk('/lib/modules/{}/kernel'.format(version)):
        ko_file_list.extend(files)
    # Checks to see if all running kernel objects are found in ko_file_list
    with open('/proc/modules') as open_modules:
        for i in open_modules:
            if (i.split()[0] + ".ko") not in ko_file_list:
                # Some .ko files replace '-' with '_' when checked in /proc/modules
                # Have to replace to check and replace x86-64 with x86_64
                if (i.split()[0].replace('_', '-').replace('x86-64', 'x86_64') + ".ko") not in ko_file_list:
                    ko_list.append(i)
    return ko_list


def pid_binary(pids):
    '''
    Accepts a list of pids and returns
    a list of the pids binary names.
    '''

    binary_names = []
    for pid in pids:
        try:
            binary = os.readlink('/proc/{}/exe'.format(pid))
            binary_names.append(binary)
        except FileNotFoundError:    # Cannot read exe link
            with open('/proc/{}/stat'.format(pid)) as open_stat:
                binary_names.append(open_stat.readline().split()[1])
        except OSError:    # proc has already terminated
            continue
    return binary_names


def banner():
    banner = '\n'.join([
        "  _____                ______ _           _",
        " |  __ \              |  ____(_)         | |",
        " | |__) | __ ___   ___| |__   _ _ __   __| | ___ _ __",
        " |  ___/ '__/ _ \ / __|  __| | | '_ \ / _` |/ _ \ '__|",
        " | |   | | | (_) | (__| |    | | | | | (_| |  __/ |",
        " |_|   |_|  \___/ \___|_|    |_|_| |_|\__,_|\___|_|",
        "\n                 {}",
        "                 Author: wakef33\n",
    ]).format(__version__)

    banner_colors = Colors()
    banner_colors.banner(banner)


def main():

    colors = Colors()
    if os.geteuid() != 0:
        colors.warning("ProcFinder must be run as root.")
        raise SystemExit()

    parser = argparse.ArgumentParser(description='ProcFinder attempts to find signs of malware by checking in /proc')
    parser.add_argument('-p', '--pids', dest='pids', help='Comma seperated list of PIDs to search against', required=False, nargs='*', type=int)
    parser.add_argument('-q', '--quiet', dest='quiet', help='Do not print binary name associated with the PID', required=False, action='store_true')
    parser.add_argument('-v', '--version', dest='version', help='Prints version number', required=False, action='store_true')
    args = parser.parse_args()

    if args.version:
        print(__version__)
        raise SystemExit()

    p = ProcFinder()
    banner()

    # TODO: Fix ps_check with --pids
    if args.pids != None:
        p.pids = args.pids

    def present_test(check, header, pass_test, fail_test):
        colors.note(header)
        if check == -1:
            colors.warning("Error: /proc/net/packet does not exist\n")
        elif len(check) == 0:
            colors.note(pass_test)
        else:
            colors.warning(fail_test)
            print(check)
            if fail_test == "Found Suspicious Kernel Objects":
                print()
            elif args.quiet == False:
                print(pid_binary(check))
                print()

    colors.note("PIDs Running")
    print(p)
    print()

    present_test(p.deleted_check(), "Deleted Binaries Check", "No Deleted Binaries Running Found\n", "Found Deleted Binaries Running")
    present_test(p.path_check(), "PATH Environment Variables Check", "No Suspicious PATH Environment Variables Found\n", "Found Suspicious PATH Environment Variables")
    present_test(p.promiscuous_check(), "Promiscuous Binaries Check", "No Promiscuous Binaries Running Found\n", "Found Promiscuous Binaries Running")
    present_test(p.ps_check(), "Ps Check", "No Suspicious PIDs Found\n", "Found Suspicious PIDs")
    present_test(p.thread_check(), "Thread Check", "No Suspicious Threads Found\n", "Found Suspicious Threads")
    present_test(p.cwd_check(), "CWD Check", "No Suspicious CWD Found\n", "Found Suspicious CWD")
    present_test(p.preload_check(), "LD_PRELOAD Check", "No Suspicious LD_PRELOAD Found\n", "Found Suspicious LD_PRELOAD")
    present_test(ko_check(), "Kernel Objects Check", "No Suspicious Kernel Objects Found", "Found Suspicious Kernel Objects")

if __name__ == '__main__':
    main()
