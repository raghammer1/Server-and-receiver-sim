# Reliable text transfer over UDP

A Python networking learning project with a sender and receiver communicating over loopback UDP. Reliability is implemented above UDP using sequence numbers, acknowledgements and retransmission. It is not a production replacement for TCP.

## Architecture

- `sender.py` maintains a sliding send window, listens for ACKs and retransmits unacknowledged data. Forward data loss and reverse ACK loss are configurable.
- `receiver.py` buffers incoming segments, writes ordered text and sends cumulative acknowledgements. SYN and FIN packets manage setup and shutdown.
- Both programs write event logs and summary counters. The sender uses a fixed random seed, which makes the loss simulation more repeatable but is not evidence of general reliability.

## Run locally

Python 3 and its standard library are sufficient. Use two terminals in this repository. Start the receiver first:

```sh
python3 receiver.py 50001 50000 received 3000
```

Then start the sender:

```sh
python3 sender.py 50000 50001 asyoulik 3000 1000 10 10
```

Receiver arguments: receiver port, sender port, output basename, window size. Sender arguments: sender port, receiver port, input basename, window size in bytes, retransmission timeout in milliseconds, forward loss percentage (integer 0–100), reverse loss percentage (integer 0–100). The scripts append `.txt` to the basenames. Existing output and log files may be overwritten; use a disposable working directory for experiments.

Compare the resulting text with the input. Start with `0 0` loss, then introduce loss and inspect retransmission counters. Ports must be available on `127.0.0.1`.

## Limits and next steps

The implementation handles text, uses global protocol state and threads, and has no checked-in automated regression suite. It does not implement TCP congestion control, encryption, authentication or a production network stack. Sequence wraparound, large files, Unicode boundaries and extreme loss deserve explicit tests. No throughput or production-scale claim is made.

The portfolio's browser simulation illustrates the ideas; it does not execute these Python sockets or reproduce every protocol detail.

## Verification on 2 October 2026

A 5,120-byte text fixture transferred byte-for-byte on loopback with zero loss and with 10% simulated loss in each direction, using a 3,000-byte window and 200 ms timeout. Both processes exited successfully. These two smoke checks do not establish comprehensive reliability or throughput. Use integer percentages (`10`), not fractional probabilities (`0.1`).
