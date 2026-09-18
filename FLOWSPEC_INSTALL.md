# FastNetMon CE FlowSpec: Debian 13 runbook

This build was tested with GoBGP `v3.12.0` and the local GoBGP gRPC API on
`127.0.0.1:50051`.

## Build dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake pkg-config \
  libboost-program-options-dev libboost-regex-dev \
  libboost-serialization-dev libboost-thread-dev \
  liblog4cpp5-dev libssl-dev libncurses-dev \
  libgrpc-dev libgrpc++-dev libprotobuf-dev libabsl-dev \
  protobuf-compiler protobuf-compiler-grpc libgtest-dev
```

## Configure and build

```bash
cmake -S src -B build-step2-gobgp \
  -DBUILD_TESTS=ON \
  -DDO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD=OFF \
  -DENABLE_GOBGP_SUPPORT=ON \
  -DLINK_WITH_ABSL=ON \
  -DENABLE_CAPNP_SUPPORT=OFF \
  -DENABLE_MONGODB_SUPPORT=OFF \
  -DENABLE_AF_XDP_SUPPORT=OFF \
  -DENABLE_PCAP_SUPPORT=OFF \
  -DKAFKA_SUPPORT=OFF \
  -DCLICKHOUSE_SUPPORT=OFF

cmake --build build-step2-gobgp --target fastnetmon fastnetmon_client --parallel "$(nproc)"
```

The verified CMake target names are `fastnetmon` and `fastnetmon_client`.

## Install

With the default Linux CMake setting `SET_ABSOLUTE_INSTALL_PATH=ON`, the
repository install rules place the binaries here:

```text
/usr/sbin/fastnetmon
/usr/bin/fastnetmon_client
```

The generated systemd unit also runs `/usr/sbin/fastnetmon`.

```bash
sudo cmake --install build-step2-gobgp
sudo systemctl daemon-reload
```

Review `/etc/fastnetmon.conf` before starting the service; CMake installs the
repository example configuration there.

## FastNetMon FlowSpec settings

Set these values in `/etc/fastnetmon.conf` (replace placeholders):

```ini
gobgp = on
gobgp_flowspec = on
gobgp_flowspec_redirect_ipv4 = <SCRUBBER_IP>

gobgp_flowspec_port_detection = on
gobgp_flowspec_port_min_samples = 10
gobgp_flowspec_port_dominance_percent = 70

gobgp_flowspec_notify_script_path = /usr/local/bin/notify_about_flowspec.sh
```

An empty `gobgp_flowspec_notify_script_path` disables separate FlowSpec
AddPath/DeletePath success notifications. The script receives `add <victim-ip>`
or `delete <victim-ip>` and the detailed result through stdin.

## GoBGP requirements

`gobgpd` must run locally, expose its gRPC API to FastNetMon on
`127.0.0.1:50051`, and establish IPv4 FlowSpec AFI/SAFI with the router.
This implementation was tested against GoBGP `v3.12.0`.

Minimal `/etc/gobgpd.conf` example. All addresses and ASNs below are examples;
replace them with your deployment values.

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.10"             # example GoBGP router ID

[api-server.config]
  listen-addresses = ["127.0.0.1:50051"]

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.1"     # example MX480 address
    peer-as = 65002                     # example MX480 ASN

  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
      enabled = true
```

The MX480 policy/configuration must separately accept IPv4 FlowSpec and the
RFC 8955 redirect-to-IPv4 extended community.

## Restart requirement

FastNetMon stores AddPath UUID lifecycle state only in memory. After a
FastNetMon restart it cannot withdraw paths installed before that restart.
In this deployment model, restart `gobgpd` before starting FastNetMon so old
dynamic FlowSpec paths are cleared from GoBGP:

```bash
sudo systemctl restart gobgpd
sudo systemctl restart fastnetmon
```

Do not assume that a simple BGP session reset clears the GoBGP RIB.

## Verify

```bash
systemctl status fastnetmon
systemctl status gobgpd
gobgp neighbor
gobgp global rib -a ipv4-flowspec
```

## Relevant tests

```bash
cmake --build build-step2-gobgp --target fastnetmon_tests --parallel "$(nproc)"

./build-step2-gobgp/fastnetmon_tests \
  --gtest_filter='flowspec.*:gobgp_flowspec_rule_builder.*:gobgp_flowspec_port_classifier.*:gobgp_flowspec_notification_formatter.*'
```
