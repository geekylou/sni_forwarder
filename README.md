# sni_forwarder
A simple program to parse the SNI data in a TLS request and forward the network request to the requested host.  This allows reverse proxies which have no knowledge of the hosts data.

## Building
To build use the standard rust cargo build system as follows:
cargo build:

cargo build

Or for release builds:

cargo build --release

This will produce a executable in target which can be run as follows:

sni_forwarder -f <config_filename>.yaml

## Config

The config filename simply contains the following entries.
- Host: This is the address the forwarder will bind to for incomming requests.
- Hosts: This is a list of addresses the forward will forward.  The first entry is the host requested, followed by the address the forwarder should connect to service that request.
