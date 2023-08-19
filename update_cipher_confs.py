#!/usr/bin/env python3

import argparse
import re
import sys
import os

# Variable Declaration
java_conf = ""
ssh_conf = "/etc/ssh/sshd_config"

regex_init = r'^jdk[.]tls[.]disabledAlgorithms(.*\\\n)*.*'
regex_java = r'^jdk[.]tls[.]disabledAlgorithms=.*'
regex_ssh_ciphers = r'^Ciphers .*'
regex_ssh_macs = r'^Macs .*'
regex_ssh_kex = r'^KexAlgorithms .*'

backup_dir = "/storetmp/"
java_conf_path = backup_dir + "cipherJavaBackup.conf"
ssh_ciphers_conf_path = backup_dir + "cipherCiphersBackup.conf"
ssh_macs_conf_path = backup_dir + "cipherMacsBackup.conf"
ssh_kex_conf_path = backup_dir + "cipherKexBackup.conf"

qconf_install_dir = ""
initial_java_conf_path = qconf_install_dir + "initialcipherJava.conf"
initial_ssh_ciphers_conf_path = qconf_install_dir + "initialcipherCiphers.conf"
initial_ssh_macs_conf_path = qconf_install_dir + "initialcipherMacs.conf"
initial_ssh_kex_conf_path = qconf_install_dir + "initialcipherKex.conf"

def initialize_parser():
    """ Initialize parser
    Returns:
        The user input for options
    """

    # Initialize parser
    parser = argparse.ArgumentParser(
        prog='update_cipher_confs',
        description='Script enables adding/removing ciphers in java.security or sshd_config')

    # Initialize subparser
    subparser = parser.add_subparsers(dest='command')
    current = subparser.add_parser('current', help='Display a list of ciphers in a security configuration file')
    add = subparser.add_parser('add', help='Add ciphers to a security configuration file')
    remove = subparser.add_parser('remove', help='Delete ciphers from a security configuration file')
    backup = subparser.add_parser('backup', help='Back up ciphers to files')
    restore = subparser.add_parser('restore', help='Restore ciphers from backup files')

    # Add argument to current subparser
    current.add_argument('-t', '--type', required=True,
                         help='<type> can be: java or ssh')

    # Add argument to add subparser
    add.add_argument(
        '-t',
        '--type',
        required=True,
        help='<type> can be: java or ssh')
    add.add_argument(
        '-k',
        '--key',
        help='[key] is only required if <type> == ssh \n[key] can be: Ciphers, Macs, KexAlgorithms')
    add.add_argument(
        '-c',
        '--cipher',
        required=True,
        help='<cipher> is a desired cipher name to add to the key. Or it can be a list of <cipher> by enclosing them in double quotes')

    # Add argument to remove subparser
    remove.add_argument(
        '-t',
        '--type',
        required=True,
        help='<type> can be: java or ssh')
    remove.add_argument(
        '-k',
        '--key',
        help='[key] is only required if <type> == ssh \n[key] can be: Ciphers, Macs, KexAlgorithms')
    remove.add_argument(
        '-c',
        '--cipher',
        required=True,
        help='<cipher> is a desired cipher name to remove from the key. Or it can be a list of <cipher> by enclosing them in double quotes')

    #Add argument for backup subparser
    backup.add_argument(
        '-i',
        '--initialRun',
        action='store_true')

    #Add argument for restore subparser
    restore.add_argument(
        '-t',
        '--type',
        required=True,
        help='<type> can be: java or ssh')

    # Parse arguments
    args = parser.parse_args()

    return args


def convert_to_one_line():
    """ Convert jdk.tls.disabledAlgorithms to one line
    Arguments:
        None
    Returns:
        None
    """

    conf = java_conf
    regex_pattern = regex_init

    # If the values of jdk.tls.disabledAlgorithms expands multi-lines in java.security
    is_multi_line = retrieve_ciphers(conf, regex_pattern, 1)

    if is_multi_line:
        # Change to one line
        is_multi_line = retrieve_ciphers(conf, regex_pattern)
        one_line = is_multi_line.replace("\\\n", "")
        one_line = ' '.join(one_line.split())

        with open(conf, 'r') as file:
            filedata = file.read()

        converted_filedata = re.sub(
            regex_pattern,
            one_line,
            filedata,
            flags=re.MULTILINE)

        with open(conf, 'w') as file:
            file.write(converted_filedata)

        #print("\nSuccessfully converted in jdk.tls.disabledAlgorithms\n")

    # else:
    #     print("\nChanges already made in jdk.tls.disabledAlgorithms as one line\n")


def retrieve_ciphers(conf, regex_pattern, num=0):
    """ Returns the match using regex
    Arguments:
        conf: String
        regex_pattern: String
    Returns:
        The entire match of the regex pattern
    """

    with open(conf, 'r') as file:
        filedata = file.read()

    result = re.search(regex_pattern, filedata, flags=re.MULTILINE)

    return result.group(num)


def display_current_ciphers(type):
    """ Prints the file path and regex for each type of the conf files
    Arguments:
        type: String
    Returns:
        None
    """

    if type == "java":
        conf = java_conf
        regex_pattern_list = [regex_java]
    elif type == "ssh":
        conf = ssh_conf
        regex_pattern_list = [regex_ssh_ciphers, regex_ssh_macs, regex_ssh_kex]
    else:
        sys.exit("<type> can be: java or ssh")

    for regex_pattern in regex_pattern_list:
        ciphers_list = retrieve_ciphers(conf, regex_pattern)
        print(ciphers_list + "\n")


def replace_ciphers_add(type, conf, regex_pattern, cipher):
    """ Replaces the existing list of ciphers with the new list of ciphers for add function
    Arguments:
        conf: String
        regex_pattern: String
        cipher: String
    Returns:
        None
    """

    ciphers_list = retrieve_ciphers(conf, regex_pattern)
    is_empty_cipher = re.search(
        regex_pattern[:-2] + '$', ciphers_list)

    with open(conf, 'r') as file:
        filedata = file.read()

    if is_empty_cipher:
        appended_filedata = re.sub(
            regex_pattern,
            r'\g<0>{}'.format(cipher),
            filedata,
            flags=re.MULTILINE)
    else:

        if type == "java":
            appended_filedata = re.sub(
                regex_pattern,
                r'\g<0>, {}'.format(cipher),
                filedata,
                flags=re.MULTILINE)
        else:
            appended_filedata = re.sub(
                regex_pattern,
                r'\g<0>,{}'.format(cipher),
                filedata,
                flags=re.MULTILINE)

    with open(conf, 'w') as file:
        file.write(appended_filedata)


def add_ciphers(type, cipher, key):
    """ Sets the file path and regex for each type of the conf files
    Arguments:
        type: String
        cipher: String
        key: String
    Returns:
        None
    """

    if type == "java" and key is None:
        conf = java_conf
        regex_pattern = regex_java
        conf_filename = "java.security"
        conf_keyname = "jdk.tls.disabledAlgorithms"
    elif type == "ssh" and key in ["Ciphers", "Macs", "KexAlgorithms"]:
        conf = ssh_conf
        conf_filename = "sshd_config"
        conf_keyname = key

        if key == "Ciphers":
            regex_pattern = regex_ssh_ciphers
        elif key == "Macs":
            regex_pattern = regex_ssh_macs
        elif key == "KexAlgorithms":
            regex_pattern = regex_ssh_kex
    else:
        sys.exit(f"Arguments are not valid. \nTry {sys.argv[0]} add -h")

    #print(f"Before adding {cipher} to {conf_filename}\n")
    print(f"BEFORE: ")
    display_current_ciphers(type)
    replace_ciphers_add(type, conf, regex_pattern, cipher)
    #print(f"\n\n{cipher} has been added to {conf_keyname} in {conf_filename}\n")
    print(f"AFTER: ")
    display_current_ciphers(type)


def replace_ciphers_remove(conf, regex_pattern, replacing_ciphers_list):
    """ Replaces the existing list of ciphers with the new list of ciphers for remove function
    Arguments:
        conf: String
        regex_pattern: String
        replacing_ciphers_list: String
    Returns:
        None
    """

    with open(conf, 'r') as file:
        filedata = file.read()

    deleted_filedata = re.sub(
        regex_pattern,
        replacing_ciphers_list,
        filedata,
        flags=re.MULTILINE)

    with open(conf, 'w') as file:
        file.write(deleted_filedata)


def remove_ciphers(type, cipher, key):
    """ Sets the file path and regex for each type of the conf files
    Arguments:
        type: String
        cipher: String
        key: String
    Returns:
        None
    """

    if type == "java" and key is None:
        conf = java_conf
        regex_pattern = regex_java
        conf_filename = "java.security"
        conf_keyname = "jdk.tls.disabledAlgorithms"
    elif type == "ssh" and key in ["Ciphers", "Macs", "KexAlgorithms"]:
        conf = ssh_conf

        if key == "Ciphers":
            regex_pattern = regex_ssh_ciphers
        elif key == "Macs":
            regex_pattern = regex_ssh_macs
        elif key == "KexAlgorithms":
            regex_pattern = regex_ssh_kex

        conf_filename = "sshd_config"
        conf_keyname = key
    else:
        sys.exit(
            f"Arguments are not valid. \nTry python3 {sys.argv[0]} remove -h")

    ciphers_list = retrieve_ciphers(conf, regex_pattern)

    if cipher not in ciphers_list:
        sys.exit(
            f"The cipher is not found. \nTry python3 {sys.argv[0]} current -t {type}")

    #print(f"Before removing {cipher} from {conf_filename}\n")
    print(f"BEFORE: ")
    display_current_ciphers(type)

    if type == "java":
        is_ending_cipher = re.search(r'{}$'.format(cipher), ciphers_list)

        if is_ending_cipher:
            is_only_cipher = re.search(
                r"={}$".format(cipher), ciphers_list)

            if is_only_cipher:
                removed_ciphers_list = re.sub(
                    r'{}'.format(cipher), r'', ciphers_list)
            else:
                removed_ciphers_list = re.sub(
                    r', {}'.format(cipher), r'', ciphers_list)
        else:
            removed_ciphers_list = re.sub(
                r'{}, '.format(cipher), r'', ciphers_list)
    else:
        is_ending_cipher = re.search(r'{}$'.format(cipher), ciphers_list)

        if is_ending_cipher:
            is_only_cipher = re.search(
                r"\s{}$".format(cipher), ciphers_list)

            if is_only_cipher:
                removed_ciphers_list = re.sub(
                    r'{}'.format(cipher), r'', ciphers_list)
            else:
                removed_ciphers_list = re.sub(
                    r',{}'.format(cipher), r'', ciphers_list)
        else:
            removed_ciphers_list = re.sub(
                r'{},'.format(cipher), r'', ciphers_list)

    replace_ciphers_remove(conf, regex_pattern, removed_ciphers_list)
    #print(f"\n\n{cipher} has been removed from {conf_keyname} in {conf_filename}\n")
    print(f"AFTER: ")
    display_current_ciphers(type)


def backup(initialRun):
    """ Back up the ciphers from Java.security and ssh.conf
    Arguments:
        initialRun: String
    Returns:
        None
    """

    ciphers_java = retrieve_ciphers(java_conf, regex_java)
    ciphers_ssh_ciphers = retrieve_ciphers(ssh_conf, regex_ssh_ciphers)
    ciphers_ssh_macs = retrieve_ciphers(ssh_conf, regex_ssh_macs)
    ciphers_ssh_kex = retrieve_ciphers(ssh_conf, regex_ssh_kex)

    #Declare dictionary
    if initialRun:
        path_ciphers_dict = {
            initial_java_conf_path : ciphers_java,
            initial_ssh_ciphers_conf_path: ciphers_ssh_ciphers,
            initial_ssh_macs_conf_path: ciphers_ssh_macs,
            initial_ssh_kex_conf_path: ciphers_ssh_kex
        }
    else:
        path_ciphers_dict = {
            java_conf_path: ciphers_java,
            ssh_ciphers_conf_path: ciphers_ssh_ciphers,
            ssh_macs_conf_path: ciphers_ssh_macs,
            ssh_kex_conf_path: ciphers_ssh_kex
        }

    #Loop through to call function
    for file_path, ciphers in path_ciphers_dict.items():
        if not os.path.exists(file_path):
            with open(file_path, 'w') as file:
                file.write(ciphers)


def restore(type):
    """ Restore the ciphers from back up files
    Arguments:
        type: String
    Returns:
        None
    """

    #list_regex = [regex_java, regex_ssh_ciphers, regex_ssh_macs, regex_ssh_kex]
    #list_backup_path = [java_conf_path, ssh_ciphers_conf_path, ssh_macs_conf_path, ssh_kex_conf_path]
    list_backup_ciphers = []

    if type == "java":
        conf = java_conf
        list_regex = [regex_java]
        list_backup_path = [java_conf_path]
    elif type == "ssh":
        conf = ssh_conf
        list_regex = [regex_ssh_ciphers, regex_ssh_macs, regex_ssh_kex]
        list_backup_path = [ssh_ciphers_conf_path, ssh_macs_conf_path, ssh_kex_conf_path]
    else:
        sys.exit("<type> can be: java or ssh")

    for conf_path in list_backup_path:
        with open(conf_path, 'r') as file:
            list_backup_ciphers.append(file.read())

        if os.path.exists(conf_path):
            os.remove(conf_path)

    for i in range(len(list_backup_ciphers)):

        with open(conf, 'r') as file:
            filedata = file.read()

        replaced_filedata = re.sub(
            list_regex[i],
            list_backup_ciphers[i],
            filedata,
            flags=re.MULTILINE)

        with open(conf, 'w') as file:
            file.write(replaced_filedata)


def main():
    # Use convert_to_one_line to make it easy to handle multi-lines ciphers for a key in a conf file
    convert_to_one_line()

    args = initialize_parser()
    #print(f"Calling {args.command} function on {args.type}\n")

    if args.command == "current":
        display_current_ciphers(args.type)
    elif args.command == "add":
        add_ciphers(args.type, args.cipher, args.key)
    elif args.command == "remove":
        remove_ciphers(args.type, args.cipher, args.key)
    elif args.command == "backup":
        backup(args.initialRun)
    elif args.command == "restore":
        restore(args.type)


if __name__ == '__main__':
    main()
