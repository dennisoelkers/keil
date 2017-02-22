# keil
Logging from pflog interface to GELF. Use it if you want a lightweight way to log all packets from pf on FreeBSD or OpenBSD to [Graylog](https://www.graylog.org).

## Compilation

  * Checkout the repository
  * Install the [glide package manager](https://glide.sh)
  * Run `make` in the checked out repository
  
## Syntax

```
usage: keil [<flags>] <source>

Flags:
      --help              Show context-sensitive help (also try --help-long and --help-man).
  -f, --file              Read from file instead of device
  -P, --promisc           Defines if interface is flagged promiscous
  -h, --host="localhost"  Hostname of Graylog server
  -p, --port=12201        Port of Graylog Server
      --facility="pflog"  The facility identifier used for logging

Args:
  <source>  Name of device/filename to read from
```

## Usage

The easiest way to use it would be to ron the `keil` binary with only the interface name it should capture packets from as an argument, like `keil pflog0`. This way it would use the default settings and log all GELF packets to `localhost:12201`.

If you want to change the destination host/port, log from a (pcap) file instead of an interface, switch the interface to promiscuous or change the facility used for logging, refer to the syntax.
