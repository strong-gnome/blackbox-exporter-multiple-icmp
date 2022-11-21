# Blackbox exporter



The blackbox exporter allows blackbox probing of endpoints over
HTTP, HTTPS, DNS, TCP, ICMP (single or multiple probes at one query) and gRPC.

## Running this software

### Using the docker image

*Note: You may want to [enable ipv6 in your docker configuration](https://docs.docker.com/v17.09/engine/userguide/networking/default_network/ipv6/)*

    docker run -p 9115:9115 --name blackbox_exporter --config.file=/config/blackbox.yml

### Checking the results

Visiting [http://localhost:9115/probe?target=google.com&module=icmp](http://localhost:9115/probe?target=google.com&module=icmp)
will return metrics for a ICMP probe against google.com. The `Success`
metric indicates if the probe succeeded. Adding a `debug=true` parameter
will return debug information for that probe.

### TLS and basic authentication

The Blackbox Exporter supports TLS and basic authentication. This enables better
control of the various HTTP endpoints.

To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).

Note that the TLS and basic authentication settings affect all HTTP endpoints:
/metrics for scraping, /probe for probing, and the web UI.

## Building the software

### Building with Docker

Please be aware, that local container will be built inside *golang:alpine* container, which will build binary from .go. Second action needs working Internet connection to pull public *golang* libs (like [prometheus/common](https://github.com/prometheus/common) and etc).
In case you don't have access to libs, but you are able to build binary locally, then use next order of commands:

    go build -o ./blackbox_exporter
    cp Dockerfile_build_in_local Dockerfile
    docker build -t name-of-your-image:some-tag .

To build a container from *golang:alpine* use cmds below.

    cp Dockerfile_build_in_container Dockerfile
    docker build -t blackbox_exporter .


## [Configuration](CONFIGURATION.md)

Blackbox exporter is configured via a [configuration file](CONFIGURATION.md) and command-line flags (such as what configuration file to load, what port to listen on, and the logging format and level).

Blackbox exporter can reload its configuration file at runtime. If the new configuration is not well-formed, the changes will not be applied.
A configuration reload is triggered by sending a `SIGHUP` to the Blackbox exporter process or by sending a HTTP POST request to the `/-/reload` endpoint.

To view all available command-line flags, run `./blackbox_exporter -h`.

To specify which [configuration file](CONFIGURATION.md) to load, use the `--config.file` flag.

Additionally, an [example configuration](blackbox.yml) is also available.

DNS, TCP socket, ICMP and gRPC (see permissions section) are currently supported. HTTP, HTTPS (via the `http` prober) are temporary unsupported.

This can be further limited by the `timeout` in the Blackbox exporter config file. If neither is specified, it defaults to 120 seconds.

## Permissions

The ICMP probe requires elevated privileges to function:

* *Windows*: Administrator privileges are required.
* *Linux*: either a user with a group within `net.ipv4.ping_group_range`, the
  `CAP_NET_RAW` capability or the root user is required.
  * Your distribution may configure `net.ipv4.ping_group_range` by default in
    `/etc/sysctl.conf` or similar. If not you can set
    `net.ipv4.ping_group_range = 0  2147483647` to allow any user the ability
    to use ping.
  * Alternatively the capability can be set by executing `setcap cap_net_raw+ep
    blackbox_exporter`
* *BSD*: root user is required.
* *OS X*: No additional privileges are needed.

[hub]: https://hub.docker.com/r/ggadyuchenko/blackbox-json