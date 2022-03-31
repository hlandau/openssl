ddd-01-conn-blocking
====================

Simple change of TLS_client_method to QUIC_client_method. Everything else is
abstracted, so no further changes needed.

Note that this assumes that the application spends its time blocked in libssl
calls. If the application does not call into libssl periodically, timer event
handling issues arise; see the notes on timer events in
ddd-02-conn-blocking.DISCUSSION.md. This could be handled by using
thread-assisted mode or by calling the BIO_pump function proposed for
ddd-02-conn-nonblocking periodically.
