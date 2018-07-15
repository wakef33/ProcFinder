#!/usr/bin/env python3
'''
ProcFinder parses the procfs in Linux
distributions searching for signs of malware
'''

import os
import re
import subprocess

__version__ = 'ProcFinder 0.2.7'


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
        mycolors = Colors()
        if os.name != "posix" or os.path.isdir("/proc") == False:
            mycolors.warning("ProcFinder is intended to only be ran on a *nix OS with a procfs")
            raise SystemExit()
        self.pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]


    def __repr__(self):
        return "%s" % (self.pids)


    def deleted_bin(self):
        '''
        Returns a list of PIDs whose binary has
        been deleted from disk
        '''

        deleted_binaries = []
        for pid in self.pids:
            try:
                link = os.readlink('/proc/{}/exe'.format(pid))
                if re.match('.*\(deleted\)$', link):
                    deleted_binaries.append(pid)
            except OSError:    # proc has already terminated
                continue
        return deleted_binaries


    def path(self):
        '''
        Returns a list of PIDs whose PATH environment
        varibale contains a '.'
        '''

        path_binaries = []
        for pid in self.pids:
            try:
                with open('/proc/{}/environ'.format(pid)) as open_env:
                    # Creates a list of all the environment varliables for the process
                    for i in open_env:
                        lines = i.split('\x00')
                    # Loops through each environment varliable looking for '.' in its PATH
                    for j in lines:
                        if re.match('^PATH=.*\..*', j):
                            path_binaries.append(pid)
            except OSError:    # proc has already terminated
                continue
        return path_binaries


    def promiscuous(self):
        '''
        Returns a list of PIDs who are listening
        on an interface promiscuously
        '''

        inode_list = []
        promiscuous_list = []
        with open('/proc/net/packet') as packet:
            packet_read = packet.readlines()
            for i in packet_read[1::]:
                inode_list.append(i.split()[-1])
        for pid in self.pids:
            try:
                fd_files = [fd for fd in os.listdir('/proc/{}/fd'.format(pid))]
            except OSError:    # proc has already terminated
                continue
            for link in fd_files:
                try:
                    fd_link = os.readlink('/proc/{}/fd/{}'.format(pid, link))
                    fd_match = list(map(lambda x: re.findall(x, fd_link), inode_list))
                    for i in fd_match:
                        if len(i) > 0:
                            if pid not in promiscuous_list:
                                promiscuous_list.append(pid)
                except OSError:    # proc has already terminated
                    continue
        return promiscuous_list


    def ps_check(self):
        '''
        Returns a list of PIDs whose PID do not match
        with the on disk ps and the PIDs in /proc
        '''

        ps = subprocess.Popen(['ps', '-eo', 'pid', '--no-headers'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = ps.communicate(timeout=15)[0]
        outputList = output.decode().split('\n')[:-2]
        outputStriped = [x.strip(' ') for x in outputList]
        return list(set(outputStriped).symmetric_difference(self.pids))


    def thread_check(self):
        '''
        Returns a list of PIDs whose process has
        multiple threads and a difference greater
        than 500 of the smallest and largest thread
        ID. This has a high chance of false positives,
        recommend running multiple times
        '''

        thread_list = []
        for pid in self.pids:
            try:
                thread_dirs = [thread for thread in os.listdir('/proc/{}/task'.format(pid))]
                if (int(thread_dirs[-1]) - int(thread_dirs[0])) > 1000:
                    thread_list.append(pid)
            except OSError:    # proc has already terminated
                continue
        return thread_list


    def cwd_check(self):
        '''
        Returns a list of PIDs whose cwd contains
        either /tmp, /dev/shm, or /var/tmp
        '''

        cwd_list = []
        for pid in self.pids:
            try:
                cwd_str = os.readlink('/proc/{}/cwd'.format(pid))
                if re.match('^/tmp.*|^/dev/shm.*|^/var/tmp.*', cwd_str):
                    cwd_list.append(pid)
            except OSError:    # proc has already terminated
                continue
        return cwd_list


    def preload_check(self):
        '''
        Returns a list of pids where LD_PRELOAD
        is found as an environment variable
        '''

        preload_list = []
        for pid in self.pids:
            try:
                with open('/proc/{}/environ'.format(pid)) as open_env:
                    # Creates a list of all the environment varliables for the process
                    for i in open_env:
                        lines = i.split('\x00')
                    # Loops through each environment varliable looking for LD_PRELOAD
                    for j in lines:
                        if re.match('LD_PRELOAD=.*', j):
                            preload_list.append(pid)
            except OSError:    # proc has already terminated
                continue
        return preload_list


# TODO: Cannot read exe link on some processes
def pid_binary(pids):
    '''
    Accepts a list of pids and returns
    a list of the pids binary names
    '''

    binary_list = []
    for pid in pids:
        try:
            binary = os.readlink("/proc/{}/exe".format(pid))
            binary_list.append(binary)
        except FileNotFoundError:    # Cannot read exe link
            continue
        except OSError:    # proc has already terminated
            continue
    return binary_list


def banner():
    banner = "\n".join([
        "  _____                ______ _           _",
        " |  __ \              |  ____(_)         | |",
        " | |__) | __ ___   ___| |__   _ _ __   __| | ___ _ __",
        " |  ___/ '__/ _ \ / __|  __| | | '_ \ / _` |/ _ \ '__|",
        " | |   | | | (_) | (__| |    | | | | | (_| |  __/ |",
        " |_|   |_|  \___/ \___|_|    |_|_| |_|\__,_|\___|_|",
        "\n                 {}",
        "                 Author: wakef33\n",
    ]).format(__version__)

    mybanner = Colors()
    mybanner.banner(banner)
    

def main():
    mycolors = Colors()
    if os.geteuid() != 0:
        mycolors.warning("ProcFinder must be run as root")
        raise SystemExit()

    myclass = ProcFinder()
    banner()

    mycolors.note("PIDs Running")
    print(myclass)
    print()

    mycolors.note("Deleted Binaries Check")
    if len(myclass.deleted_bin()) == 0:
       mycolors.note("No Deleted Binaries Running Found\n")
    else:
        mycolors.warning("Found Deleted Binaries Running")
        print(myclass.deleted_bin())
        print(pid_binary(myclass.deleted_bin()))
        print()

    mycolors.note("PATH Environment Variables Check")
    if len(myclass.path()) == 0:
        mycolors.note("No Suspicious PATH Environment Variables Found\n")
    else:
        mycolors.warning("Found Suspicious PATH Environment Variables")
        print(myclass.path())
        print(pid_binary(myclass.path()))
        print()

    mycolors.note("Promiscuous Binaries Check")
    if len(myclass.promiscuous()) == 0:
        mycolors.note("No Promiscuous Binaries Running Found\n")
    else:
        mycolors.warning("Found Promiscuous Binaries Running")
        print(myclass.promiscuous())
        print(pid_binary(myclass.promiscuous()))
        print()

    mycolors.note("Ps Check")
    if len(myclass.ps_check()) == 0:
       mycolors.note("No Suspicious PIDs Found\n")
    else:
        mycolors.warning("Found Suspicious PIDs")
        print(myclass.ps_check())
        print(pid_binary(myclass.ps_check()))
        print()

    mycolors.note("Thread Check")
    if len(myclass.thread_check()) == 0:
        mycolors.note("No Suspicious Threads Found\n")
    else:
        mycolors.warning("Found Suspicious Threads")
        print(myclass.thread_check())
        print(pid_binary(myclass.thread_check()))
        print()

    mycolors.note("CWD Check")
    if len(myclass.cwd_check()) == 0:
        mycolors.note("No Suspicious CWD Found\n")
    else:
        mycolors.warning("Found Suspicious CWD")
        print(myclass.cwd_check())
        print(pid_binary(myclass.cwd_check()))
        print()

    mycolors.note("LD_PRELOAD Check")
    if len(myclass.preload_check()) == 0:
        mycolors.note("No Suspicious LD_PRELOAD Found\n")
    else:
        mycolors.warning("Found Suspicious LD_PRELOAD")
        print(myclass.preload_check())
        print(pid_binary(myclass.preload_check()))
        print()
    

if __name__ == '__main__':
    main()
