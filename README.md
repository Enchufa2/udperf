# udperf

A kind of UDP-only `iperf`, but more versatile and with advanced features:

- RAW sockets (custom MAC)
- Custom payload
- CPU performance counters reporting
- Run with a specified maximum latency

## Compilation

```bash
autoreconf --install
./configure --enable-cpu-counters --enable-dma-latency
make
```

## Basic usage

Client:

```bash
$ ./udperf 127.0.0.1 1234 -vv
1480522119.915245 0.000000 [7] payload
1480522120.915140 0.999895 [7] payload
1480522121.915149 1.000009 [7] payload
^C
```

Server:

```bash
$ ./udperf -l 1234 -vv
1480522119.915345 0.000000 [7] payload
1480522120.915153 0.999808 [7] payload
1480522121.915163 1.000010 [7] payload
^C
```

See `./udperf -h` for more details.
