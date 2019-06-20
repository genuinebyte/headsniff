# Headsniff
Headsniff is a program designed to sniff the data from the header of packets that
travel through a network interface.

## Command Line Arguments
```
USAGE:
    headsniff [OPTIONS] <INTERFACE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --ip-blacklist <IP_BLACKLIST>      
        --ip-whitelist <IP_WHITELIST>      
        --mac-blacklist <MAC_BLACKLIST>    
        --mac-whitelist <MAC_WHITELIST>    

ARGS:
    <INTERFACE>    Sets the interface to listen on
```