#!/usr/bin/python3
'''
VERSION = '0.2.6'
ProcFinder checks various locations for
signs of malware running
'''

import os
import re
import subprocess

GREEN = '\033[1;32m'
RED = '\033[1;91m'
WHITE = '\033[0m'
BLUE = '\033[0;94m'


class ProcFinder():


    def __init__(self):
        self.pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]


    def __repr__(self):
        return "%s" % (self.pids)


    def deleted_bin(self):
        ''' 
        Loops through every running process trying
        to files that have been deleted and
        returns a list of pids
        '''

        deleted_binaries = []
        for pid in self.pids:
            try:
                link = os.readlink('/proc/{}/exe'.format(pid))
                if re.match('.*\(deleted\)$', link):
                    deleted_binaries.append(pid)
            except IOError:    # proc has already terminated
                continue
        return deleted_binaries


    def path(self):
        '''
        Loops through every running process trying to
        find suspicious PATH environment variables and
        returns a list of pids 
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
            except IOError:    # proc has already terminated
                continue
        return path_binaries


    def promiscuous(self):
        '''
        Finds processes that are listening
        on an interface promiscuously
        '''

        inode_list = []
        promiscuous_list = []
        with open('/proc/net/packet') as packet:
            packet_read = packet.readlines()
            for i in packet_read[1::]:
                inode_list.append(i.split()[-1])
        for pid in self.pids:
            fd_files = [fd for fd in os.listdir('/proc/{}/fd'.format(pid))]
            for link in fd_files:
                try:
                    fd_link = os.readlink('/proc/{}/fd/{}'.format(pid, link))
                    fd_match = list(map(lambda x: re.findall(x, fd_link), inode_list))
                    for i in fd_match:
                        if len(i) > 0:
                            if pid not in promiscuous_list:
                                promiscuous_list.append(pid)
                except:
                    continue
        return promiscuous_list


    def ps_check(self):
        '''
        Returns a list of unique pids by
        comparring the pid list from the on
        disk ps to the pids found in /proc
        '''

        ps = subprocess.Popen(['ps', '-eo', 'pid', '--no-headers'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        output = ps.communicate(timeout=15)[0]
        outputList = output.decode().split('\n')[:-2]
        outputStriped = [x.strip(' ') for x in outputList]
        return list(set(outputStriped).symmetric_difference(self.pids))


    def thread_check(self):
        '''
        Returns a list of pids where the process
        has multiple threads and a difference
        greater than 500 of the smallest  and largest
        thread ID. Has a high chance of false positives,
        recommend running multiple times
        '''

        thread_list = []
        for pid in self.pids:
            thread_dirs = [thread for thread in os.listdir('/proc/{}/task'.format(pid))]
            if (int(thread_dirs[-1]) - int(thread_dirs[0])) > 500:
                thread_list.append(pid)
        return thread_list


    def cwd_check(self):
        '''
        Returns a list of pids whose cwd
        is either /tmp, /dev/shm, or /var/tmp
        '''

        cwd_list = []
        for pid in self.pids:
            cwd_str = os.readlink('/proc/{}/cwd'.format(pid))
            if re.match('^/tmp.*|^/dev/shm.*|^/var/tmp.*', cwd_str):
                cwd_list.append(pid)
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
            except IOError:    # proc has already terminated
                continue
        return preload_list


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
        except FileNotFoundError:   # Cannot open /proc/PID/exe
            continue
    return binary_list


def banner():
    print("\n" + BLUE)
    print("============================================================")
    print("  ####  ####  ##### ####    #### ### #   # ###  #### ####   ")
    print("  #   # #   # #   # #       #     #  ##  # #  # #    #   #  ")
    print("  ####  ####  #   # #       ####  #  # # # #  # #### ####   ")
    print("  #     #   # #   # #       #     #  #  ## #  # #    #   #  ")
    print("  #     #   # ##### ####    #    ### #   # ###  #### #   #  ")
    print("============================================================")
    print("\n" + WHITE)


if __name__ == '__main__':
    myclass = ProcFinder()
    banner()
    print(GREEN + "Pids Running..." + WHITE)
    print(myclass)
    print(GREEN + "Deleted Binaries Running..." + WHITE)
    print(myclass.deleted_bin())
    print(pid_binary(myclass.deleted_bin()))
    print(GREEN + "Strange Path Binaries..." + WHITE)
    print(myclass.path())
    print(pid_binary(myclass.path()))
    print(GREEN + "Promiscuous Binaries..." + WHITE)
    print(myclass.promiscuous())
    print(pid_binary(myclass.promiscuous()))
    print(GREEN + "ps check..." + WHITE)
    print(myclass.ps_check())
    print(pid_binary(myclass.ps_check()))
    print(GREEN + "Thread check..." + WHITE)
    print(myclass.thread_check())
    print(pid_binary(myclass.thread_check()))
    print(GREEN + "cwd check..." + WHITE)
    print(myclass.cwd_check())
    print(pid_binary(myclass.cwd_check()))
    print(GREEN + "LD_PRELOAD check..." + WHITE)
    print(myclass.preload_check())
    print(pid_binary(myclass.preload_check()))

