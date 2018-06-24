#!/usr/bin/python3
VERSION = '0.0.2'

import os
import re
import subprocess

# Creates a list of PIDs of all currently running processes
pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

# Colors
GREEN = '\033[1;32m'
RED = '\033[1;91m'
WHITE = '\033[0m'
BLUE = '\033[0;94m'



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



'''
Loops through every running process trying to
find suspicious PATH environment variables
'''
def path():
    foundPATH = 0
    print(GREEN + '[+]' + WHITE + " Checking for suspicious PATH environment variables...")
    for pid in pids:
        try:
            open_env = open(os.path.join('/proc', pid, 'environ'))
            read_env = open_env.readlines()
            open_env.close()
            # Creates a list of all the environment varliables for the process
            for i in read_env:
                lines = i.split('\x00')
            # Loops through each environment varliable looking for '.' in its PATH
            for j in lines:
                if re.match('^PATH=.*\..*', j):
                    if foundPATH == 0:
                        print("\n" + RED + '[-]' + WHITE + " Found suspicious PATH environment variable(s)")
                    foundPATH = 1    # Flips variable if '.' is found in any process PATH variable
                    binary = os.readlink("/proc/{}/exe".format(pid))
                    print(RED + '[-]' + WHITE + ' {} ({}) has \'.\' in its PATH'.format(binary,pid))
                    print(RED + '[-]' + WHITE + ' ' + j)
        except IOError:    # proc has already terminated
            continue
    if foundPATH == 0:
        print(GREEN + '[+]' + WHITE + " No suspicious PATH environment variables found.")



'''
Files common binaries to check if they
are either an ELF or symbolic link
'''
def file_type():
    print('\n' + GREEN + '[+]' + WHITE + " Checking for suspicious common binaries...")
    # /bin/bashScript and /bin/bashScriptTwo are test cases
    files_to_be_checked = [
        'file', '/bin/bashScript', '/bin/su', '/usr/bin/ssh', '/bin/bashScriptTwo',
        '/usr/bin/ssh', '/bin/ps', '/bin/netstat', '/bin/ss',
        '/sbin/ip', '/bin/ls', '/sbin/ifconfig', '/bin/bash',
        '/bin/mount', '/bin/rm', '/usr/bin/find', '/bin/cat'
        ]
    
    # egrep -v 'ELF|symbolic link|cannot open' every file in files_to_be_checked
    grep = subprocess.Popen(['egrep', '-v', 'ELF|symbolic link|cannot open'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    files = subprocess.Popen(files_to_be_checked, stdin=subprocess.PIPE, stdout=grep.stdin)
    
    try:
        output = grep.communicate(timeout=15)[0]
        outputList = output.decode().split('\n')
        if len(output.decode()) > 0:
            print("\n" + RED + '[-]' + WHITE + " Found file(s) that are either not an ELF or symbolic link")
            for i in outputList:
                if len(i) > 1:
                    print(RED + '[-]' + WHITE + ' ' + i)
        else:
            print(GREEN + '[+]' + WHITE + " No suspicious common binaries found.")
    except TimeoutExpired:
        grep.kill()
        output = grep.communicate()[0]



'''
Loops through every running process trying to
files that have been deleted
'''
def deleted_bin():
    foundDEL = 0
    print('\n' + GREEN + '[+]' + WHITE + " Checking for running deleted binaries...")
    for pid in pids:
        try:
            link = os.readlink(os.path.join('/proc', pid, 'exe'))
            if re.match('.*\(deleted\)$', link):
                if foundDEL == 0:    # Flips variable if deleted binary is found
                    print("\n" + RED + '[-]' + WHITE + " Found deleted running binary(s)")
                foundDEL = 1
                print(RED + '[-]' + WHITE + ' {} ({}) is a deleted running binary'.format(link, pid))
        except IOError:    # proc has already terminated
            continue
    if foundDEL == 0:
        print(GREEN + '[+]' + WHITE + " No deleted running binaries found.")



if __name__ == "__main__":
    banner()
    path()
    file_type()
    deleted_bin()
    print("\n" + GREEN + '[+]' + WHITE + " Done")
