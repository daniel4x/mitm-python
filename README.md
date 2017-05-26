# mitm-python

A keep it simple project demonstrate how to perform a man in the middle attack with python + scapy.

![alt text]( docs/Man_in_the_Middle.jpg "mitm attack jpg")

## Requirements:

- Python version 2.7.13 (recommended), or above ...
- It's recommended to use python virtual env in order to organize the project and manage your dependencies. 
- dependencies: <br/>
Python fire for command line interface: `pip install fire`<br/>
Scapy: `pip install scapy` <br/>
libdnet: from git source: `git https://github.com/dugsong/libdnet` or from there's [official site](http://libdnet.sourceforge.net/).
If you are using git source then compile and run with `./configure && make` and the install the model using `python setup.py install`, setup.py can be found at the python directory in libdnet.

## Running:

`python app.py -h` - show help<br/>
`python app.py target_ip router_ip interface` - run the attack <br/>
Example:<br/>
`python app.py 192.168.1.39 192.168.1.1 en0` - en0 is the default interface for OS X.

Remember:exclamation: the script only using arp poisoning in order to "steal" the session between your target and some access point.
You may want to use Wireshark to inspect the target traffic or different tools for getting passwords or forging cookies for stealing sessions.

:exclamation: This script made for learning purpose :exclamation: