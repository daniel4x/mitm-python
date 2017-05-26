import fire
import re

from sys import argv
from interface.constants import SIGNATURE
from interface.mitm import mitm


def attack(ip, r, interface):
    """
    Trigger a man in the middle attack using arp poisoning method
    :param ip: target ip address 
    :param r: router ip address
    :param interface: interface to operate on
    :return: None
    """
    if validator(ip) and validator(r):
        mitm(ip, r, interface)
    else:
        raise ValueError(SIGNATURE + 'arguments error, target ip or router ip not follows any ip pattern\n',
                         'given: ip=' + ip,
                         ' r=' + r)


def validator(ip):
    """
    check if a given ip follows ip regex pattern 
    :param ip: string to validate
    :return: true if the string follows the ip regex pattern,
    otherwise return false
    """
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) is not None:
        return True
    return False


if __name__ == '__main__':
    if argv[1] == '-h':
        # help
        print('\n~~~~~~~~~~~~~~~~~~~~ Help ~~~~~~~~~~~~~~~~~~~~\n')
        print('Usage: sudo python app.py target-ip router-ip interface')
        print('e.g    sudo python app.py 192.168.1.15 192.168.1.1 en0')
        print('Note! sudo is required only in case you want enable port forwarding\n'
              'it\'s optional and can be done manually instead on your operating system.')
        print('\n~~~~~~~~~~~~~~~~~~~~ End Help ~~~~~~~~~~~~~~~~~~~~\n')
    elif argv[1] == '-guided':
        # use guided mode, to be implemented soon ...
        pass

    else:
        # for users who knows exactly what they want
        fire.Fire(attack)
