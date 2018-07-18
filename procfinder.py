#!/usr/bin/env python3
'''
ProcFinder parses the procfs in Linux
distributions searching for signs of malware.
'''

import os
import re
import subprocess

__version__ = 'ProcFinder 0.3.0'


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
        class_colors = Colors()
        if os.name != "posix" or os.path.isdir("/proc") == False:
            class_colors.warning("ProcFinder is intended to only be ran on a *nix OS with a procfs.")
            raise SystemExit()
        self.pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]


    def __str__(self):
        return "{}".format(self.pids)


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

        if os.path.isfile("/proc/net/packet") == False:
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
        output = ps.communicate(timeout=15)[0]
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
                    for i in open_env:
                        env_list = i.split('\x00')
                    # Loops through each environment varliable looking for LD_PRELOAD
                    for j in env_list:
                        if re.match('LD_PRELOAD=.*', j):
                            preload_pids.append(pid)
            except OSError:    # proc has already terminated
                continue
        return preload_pids


# TODO: Cannot read exe link on some processes
def pid_binary(pids):
    '''
    Accepts a list of pids and returns
    a list of the pids binary names.
    '''

    binary_names = []
    for pid in pids:
        try:
            binary = os.readlink("/proc/{}/exe".format(pid))
            binary_names.append(binary)
        except FileNotFoundError:    # Cannot read exe link
            continue
        except OSError:    # proc has already terminated
            continue
    return binary_names


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

    banner_colors = Colors()
    banner_colors.banner(banner)
    

def main():
    colors = Colors()
    if os.geteuid() != 0:
        colors.warning("ProcFinder must be run as root.")
        raise SystemExit()

    p = ProcFinder()
    banner()

    colors.note("PIDs Running")
    print(p)
    print()

    del_check = p.deleted_check()
    colors.note("Deleted Binaries Check")
    if len(del_check) == 0:
       colors.note("No Deleted Binaries Running Found\n")
    else:
        colors.warning("Found Deleted Binaries Running")
        print(del_check)
        print(pid_binary(del_check))
        print()

    path_check = p.path_check()
    colors.note("PATH Environment Variables Check")
    if len(path_check) == 0:
        colors.note("No Suspicious PATH Environment Variables Found\n")
    else:
        colors.warning("Found Suspicious PATH Environment Variables")
        print(path_check)
        print(pid_binary(path_check))
        print()

    promiscuous_check = p.promiscuous_check()
    colors.note("Promiscuous Binaries Check")
    if p.promiscuous_check() == -1:
        colors.warning("Error: /proc/net/packet does not exist\n")
    elif len(p.promiscuous_check()) == 0:
        colors.note("No Promiscuous Binaries Running Found\n")
    else:
        colors.warning("Found Promiscuous Binaries Running")
        print(promiscuous_check)
        print(pid_binary(promiscuous_check))
        print()

    ps_check = p.ps_check()
    colors.note("Ps Check")
    if len(ps_check) == 0:
        colors.note("No Suspicious PIDs Found\n")
    else:
        colors.warning("Found Suspicious PIDs")
        print(ps_check)
        print(pid_binary(ps_check))
        print()

    thread_check = p.thread_check()
    colors.note("Thread Check")
    if len(thread_check) == 0:
        colors.note("No Suspicious Threads Found\n")
    else:
        colors.warning("Found Suspicious Threads")
        print(thread_check)
        print(pid_binary(thread_check))
        print()

    cwd_check = p.cwd_check()
    colors.note("CWD Check")
    if len(cwd_check) == 0:
        colors.note("No Suspicious CWD Found\n")
    else:
        colors.warning("Found Suspicious CWD")
        print(cwd_check)
        print(pid_binary(cwd_check))
        print()

    preload_check = p.preload_check()
    colors.note("LD_PRELOAD Check")
    if len(preload_check) == 0:
        colors.note("No Suspicious LD_PRELOAD Found\n")
    else:
        colors.warning("Found Suspicious LD_PRELOAD")
        print(preload_check)
        print(pid_binary(preload_check))
        print()
    

if __name__ == '__main__':
    main()
