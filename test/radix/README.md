RADIX 6D Test Framework
=======================

This directory contains the RADIX test suite framework for testing network
protocol implementations. It is currently used for testing QUIC. The framework
is a six-dimension script-driven facility to support execution of

- multi-stream
- multi-client
- multi-server
- multi-thread
- multi-process (in future)
- multi-node (in future)

test vignettes for QUIC or other protocols. Unlike the older [multistream test
framework](../quic_multistream_test.c), it does not assume a single client and a
single server. Examples of vignettes designed to be supported by the RADIX test
framework in future include:

- single client ↔ single server
- multiple clients ↔ single server
- single client ↔ multiple servers
- multiple clients ↔ multiple servers

“Multi-process” and “multi-node” means there has been some consideration given
to support of multi-process and multi-node testing in the future, though this is
not currently supported.

Architecture
------------

The RADIX test suite framework is built in four layers:

- **TERP** ([terp.c](./terp.c)), a protocol-agnostic stack-based script
  interpreter;

- the **QUIC bindings** ([quic_bindings.c](./quic_bindings.c)), which adds
  QUIC-specific test functionality to TERP;

- the **QUIC operations** ([quic_ops.c](./quic_ops.c)), which define specific
  test operations which can be invoked by QUIC unit tests on top of the basic
  infrastructure defined by the QUIC bindings;

- the QUIC unit tests ([quic_tests.c](./quic_tests.c)), which use the above
  QUIC bindings.
