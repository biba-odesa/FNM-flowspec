# FastNetMon FlowSpec MVP Plan

## 1. Project

Repository:

* GitHub: `https://github.com/biba-odesa/FNM-test.git`
* Local path: `~/FNM-test`

This is an independent FastNetMon Community Edition development fork/project.

The goal is to add BGP FlowSpec-based selective mitigation to FastNetMon.

Do not modify the original `fastnetmon-1.2.9` fork unless explicitly requested.

---

## 2. Target Architecture

The required architecture is:

```text
FastNetMon
    |
    | gRPC
    v
GoBGP
    |
    | BGP / FlowSpec
    v
Juniper MX480
    |
    | FlowSpec redirect
    v
XDP scrubbing server
```

IMPORTANT:

There is NO FRR in this architecture.

Do not introduce FRR or design around FRR.

FastNetMon communicates with local GoBGP using the existing GoBGP gRPC client.

GoBGP establishes the actual BGP session directly with the Juniper MX480.

The MX480 receives FlowSpec rules and redirects matching traffic to the mitigation/XDP server.

---

## 3. Hardware / Software Environment

Juniper:

* Model: MX480
* Junos: `21.2R3-S8.5`

Juniper FlowSpec redirect-to-IP-next-hop support exists on MX480 from Junos 18.4R1, therefore the current Junos version supports the required feature.

The desired FlowSpec action is RFC 8955-style redirect to an IPv4 next hop using the appropriate extended community.

Do NOT confuse this with:

* legacy BGP NEXT_HOP redirect
* route-target/ASN-based FlowSpec redirect
* VRF redirect

The desired action is direct IPv4 redirect-to-next-hop.

GoBGP:

* Vendored version: `v3.12.0`
* protobuf package: `github.com/osrg/gobgp/v3/api`
* FastNetMon references the GoBGP protobuf through `src/gobgp_client/gobgp.proto`

FlowSpec:

* AFI: IPv4 / AFI 1
* SAFI: FlowSpec / SAFI 133

---

## 4. Goal of the MVP

Do NOT implement automatic attack classification yet.

Do NOT change FastNetMon detection thresholds.

Do NOT modify the existing packet detection pipeline.

First prove that FastNetMon can:

1. construct one static FlowSpec rule;
2. send it through GoBGP gRPC;
3. make GoBGP advertise it to the MX480;
4. make MX480 install the FlowSpec rule;
5. redirect only the matching traffic;
6. remove the rule again.

Only after this works should automatic `(protocol, destination port)` classification be implemented.

---

## 5. First Test FlowSpec Rule

Initial test rule:

```text
Destination IP:       10.10.10.10/32
Protocol:             TCP
Destination port:     443
Action:               redirect to IPv4 next-hop
Redirect next-hop:    192.168.100.50
```

Expected behavior:

```text
10.10.10.10:443/TCP  -> redirect to 192.168.100.50

10.10.10.10:80/TCP   -> normal routing
10.10.10.10:443/UDP  -> normal routing
10.10.10.10:22/TCP   -> normal routing
```

The FlowSpec rule must match ALL TCP traffic to destination port 443.

It must NOT be limited to SYN packets.

This is important because the eventual goal is mitigation of an attack against a specific service, not merely SYN packets.

---

## 6. Eventual Dynamic Behavior

Eventually FastNetMon should be able to determine something similar to:

```text
victim = 10.10.10.10
protocol = TCP
destination port = 443
```

and generate:

```text
dst 10.10.10.10/32
protocol TCP
dst-port 443
redirect -> XDP next-hop
```

If the attack is broad and cannot be safely classified, a future fallback may be:

```text
dst 10.10.10.10/32
redirect -> XDP next-hop
```

However, this automatic classifier is NOT part of the first MVP.

---

## 7. Existing FastNetMon Packet Data

Important source locations discovered during architecture analysis.

`src/fastnetmon_simple_packet.hpp`

`simple_packet_t` contains:

* source IP
* destination IP
* protocol
* source port
* destination port
* TCP flags
* packet-related information

Packet parsing examples:

```text
src/simple_packet_parser_ng.cpp
src/netflow_plugin/netflow_v5_collector.cpp
src/netflow_plugin/netflow_v9_collector.cpp
src/netflow_plugin/ipfix_collector.cpp
```

FastNetMon already has enough packet information to eventually classify destination port.

---

## 8. Existing Attack Protocol Detection

`src/fastnetmon_logic.cpp`

Relevant function:

```text
detect_attack_protocol()
```

The current logic determines dominant protocol such as TCP / UDP / ICMP.

The result is stored in:

```text
attack_details_t.attack_protocol
```

Relevant files:

```text
src/attack_details.hpp
src/fastnetmon_logic.cpp
```

Current `attack_details_t` does NOT contain destination port.

Therefore the current attack decision path cannot directly produce:

```text
TCP + destination port 443
```

without additional classification logic.

Do not add this complexity to the first MVP.

---

## 9. Packet Bucket / Future Classifier

Relevant source:

```text
src/packet_bucket.hpp
```

There is packet-level information available there.

Also relevant:

```text
src/fastnetmon_types.hpp
```

Connection tracking exists, but it is not currently the desired production classifier.

`process_flow_tracking_table()` in:

```text
src/fastnetmon_logic.cpp
```

was inspected.

It is incomplete / not currently part of the required attack decision path and counts unique flows rather than directly providing the desired traffic-volume classification.

Future classifier idea:

After the existing ban decision:

1. inspect packet bucket;
2. filter packets for the attacked destination;
3. group by `(protocol, destination_port)`;
4. weight traffic by packet count / sampling ratio;
5. select a dominant tuple only if confidence is sufficiently high;
6. otherwise avoid a selective rule or use a broader fallback.

A possible confidence threshold discussed was approximately 80–90%, but this is NOT finalized and must not be implemented yet.

---

## 10. Existing FlowSpec Implementation

FastNetMon already contains FlowSpec data structures and encoders.

Relevant files:

```text
src/bgp_protocol_flow_spec.hpp
src/bgp_protocol_flow_spec.cpp
```

Important type:

```text
flow_spec_rule_t
```

It already supports components including:

* destination prefix
* source prefix
* protocol
* source port
* destination port
* TCP flags
* packet length
* fragment flags
* FlowSpec actions

Existing helper methods include:

```text
set_destination_subnet_ipv4()
add_protocol()
add_destination_port()
```

Existing encoder:

```text
encode_bgp_flow_spec_elements_as_mp_nlri()
```

in:

```text
src/bgp_protocol_flow_spec.cpp
```

Relevant location found during analysis:

```text
src/bgp_protocol_flow_spec.cpp:289
```

There is also:

```text
encode_bgp_flow_spec_elements_into_bgp_mp_attribute(..., false)
```

around:

```text
src/bgp_protocol_flow_spec.cpp:525
```

These existing encoders should be reused rather than writing a second FlowSpec NLRI encoder.

---

## 11. Existing Redirect Implementations — Important

The existing FastNetMon FlowSpec code has multiple redirect concepts.

Existing:

```text
FLOW_SPEC_ACTION_REDIRECT
```

currently uses:

```text
redirect_as
redirect_value
```

This is an ASN/local-admin style redirect and is NOT the desired direct IPv4 next-hop redirect for this project.

Therefore do NOT simply reuse the existing `FLOW_SPEC_ACTION_REDIRECT` path unchanged.

There is also:

```text
flow_spec_rule_t::ipv4_nexthops
```

and:

```text
bgp_extended_community_element_flow_spec_ipv4_next_hop_t
```

The latter was found around:

```text
src/bgp_protocol_flow_spec.hpp:735
```

There is existing code related to IPv4 next-hop redirect.

However, the existing:

```text
build_attributes_for_flowspec_announce()
```

must NOT be blindly reused as the final implementation.

The current implementation has logic where the IPv4 redirect attribute is added under:

```text
FLOW_SPEC_ACTION_ACCEPT
```

and the overall attribute construction includes MP_REACH handling that may not be appropriate for the desired GoBGP raw `AddPath` path.

The implementation must be checked carefully against GoBGP v3.12.0.

---

## 12. GoBGP Client

Existing FastNetMon GoBGP client:

```text
src/gobgp_client/gobgp_client.hpp
src/gobgp_client/gobgp_client.cpp
```

Existing client uses raw protobuf binary fields rather than typed FlowSpec protobuf objects.

Important existing function:

```text
GrpcClient::AnnounceCommonPrefix()
```

Relevant location:

```text
src/gobgp_client/gobgp_client.cpp:57
```

The desired MVP should add a dedicated FlowSpec method instead of abusing the existing prefix announcement function.

Suggested interface:

```text
GrpcClient::AddFlowSpecIPv4(...)
```

and:

```text
GrpcClient::DeletePathByUuid(...)
```

Exact naming can be adjusted to existing project conventions.

---

## 13. GoBGP AddPath

Vendored GoBGP protobuf was inspected.

`AddPathRequest` contains:

```text
table_type
vrf_id
path
```

`AddPathResponse` contains:

```text
bytes uuid = 1
```

Relevant FastNetMon protobuf:

```text
src/gobgp_client/gobgp.proto
```

Important locations:

```text
src/gobgp_client/gobgp.proto:228
```

The expected AddPath parameters for the MVP are:

```text
table_type = GLOBAL
vrf_id = ""
```

Path family:

```text
AFI = 1
SAFI = 133
```

The FlowSpec NLRI should be supplied through:

```text
Path.nlri_binary
```

and required BGP attributes through:

```text
Path.pattrs_binary
```

---

## 14. GoBGP DeletePath

GoBGP protobuf also provides:

```text
DeletePathRequest
```

with:

```text
table_type
vrf_id
family
path
uuid
```

and:

```text
rpc DeletePath(DeletePathRequest)
```

For the MVP use the UUID returned by AddPath.

Do NOT rely on reconstructing the entire path for withdrawal if UUID-based deletion is available.

Store the returned UUID in memory.

Suggested MVP mapping:

```text
victim IP -> GoBGP path UUID
```

Restart reconciliation is a later production requirement.

---

## 15. FlowSpec NLRI Encoding for Initial Test

For:

```text
10.10.10.10/32
TCP
destination port 443
```

the component bytes identified during analysis are:

Destination:

```text
01 20 0a 0a 0a 0a
```

TCP protocol:

```text
03 81 06
```

Destination port 443:

```text
05 91 01 bb
```

Combined component sequence:

```text
01 20 0a 0a 0a 0a 03 81 06 05 91 01 bb
```

Total component length:

```text
13 bytes
```

Therefore the FlowSpec NLRI with a one-byte length field is:

```text
0d 01 20 0a 0a 0a 0a 03 81 06 05 91 01 bb
```

Do not hardcode this if the existing FlowSpec encoder can generate it correctly. The existing encoder should be preferred and unit-tested against the expected bytes.

---

## 16. Redirect Extended Community

Initial test redirect next-hop:

```text
192.168.100.50
```

The identified IPv4 FlowSpec redirect extended community bytes are:

```text
01 0c c0 a8 64 32 00 00
```

where:

```text
c0 a8 64 32 = 192.168.100.50
```

The full Extended Communities attribute for this redirect is:

```text
c0 10 08 01 0c c0 a8 64 32 00 00
```

This was verified against GoBGP v3.12.0 path-attribute processing.

---

## 17. RESOLVED — GoBGP FlowSpec `Path.pattrs_binary`

The last investigation was specifically about:

```text
GoBGP v3.12.0
AddPath
FlowSpec AFI=1 / SAFI=133
Path.nlri_binary
Path.pattrs_binary
```

For FlowSpec AFI=1 / SAFI=133, with the FlowSpec NLRI in `Path.nlri_binary`, the minimal input attributes for the MVP redirect test are:

```text
ORIGIN:
40 01 01 02

NEXT_HOP carrier (0.0.0.0):
40 03 04 00 00 00 00

EXTENDED_COMMUNITIES redirect-to-IPv4 (192.168.100.50):
c0 10 08 01 0c c0 a8 64 32 00 00
```

`ORIGIN` is required by GoBGP API path validation. `AS_PATH` is not required for a locally originated API `AddPath`.

Do **not** put `MP_REACH_NLRI` in `Path.pattrs_binary`. GoBGP v3.12.0 `api2Path()` takes the input `NEXT_HOP` as an API carrier, then creates the final `MP_REACH_NLRI` itself from `Path.family` and `Path.nlri_binary`. For FlowSpec, that final `MP_REACH_NLRI` has next-hop length zero.

The input `NEXT_HOP` value `0.0.0.0` is therefore not a FlowSpec redirect next-hop and does not implement legacy BGP NEXT_HOP redirection. The actual redirect next-hop `192.168.100.50` is encoded in the Extended Community: type `0x01`, subtype `0x0c`.

The semantics of GoBGP v3.12.0 `api2Path()` and `fixupApiPath()` were checked against that exact version's source code.

---

## 18. Configuration Changes Proposed for MVP

Potential configuration additions:

```text
gobgp_flowspec_static_test = on

gobgp_flowspec_test_destination = 10.10.10.10

gobgp_flowspec_test_protocol = tcp

gobgp_flowspec_test_destination_port = 443

gobgp_flowspec_test_redirect_ipv4 = 192.168.100.50

gobgp_flowspec_test_replace_rtbh = on
```

Exact names may be changed to match existing FastNetMon configuration conventions.

Relevant existing configuration files:

```text
src/fastnetmon_configuration_scheme.hpp
src/fastnetmon.conf
```

Previously identified locations:

```text
src/fastnetmon_configuration_scheme.hpp:61
src/fastnetmon.conf:249
```

---

## 19. MVP Ban / Unban Behavior

For the static test mode:

When FastNetMon performs the normal ban action:

```text
ban victim 10.10.10.10
```

instead of the normal RTBH behavior, it should optionally send the static FlowSpec rule:

```text
10.10.10.10/32
TCP
dst-port 443
redirect -> 192.168.100.50
```

When the victim is unbanned:

```text
unban victim 10.10.10.10
```

the corresponding GoBGP path should be deleted using its stored UUID.

The existing attack detection thresholds and detection logic must remain unchanged.

The static FlowSpec test mode should only replace the mitigation action.

---

## 20. Do Not Change These Yet

Do NOT modify:

* attack detection thresholds
* packet sampling
* `process_packet()`
* existing attack classification
* packet bucket design
* automatic port classification
* FastNetMon API protobuf
* unrelated RTBH behavior
* FRR code, because FRR is not part of the architecture
* existing production mitigation behavior outside the explicit test mode

Keep the MVP isolated.

---

## 21. Suggested Implementation Files

The following files were identified as likely minimum scope:

```text
src/fastnetmon_configuration_scheme.hpp
src/fastnetmon.conf

src/actions/gobgp_action.cpp
src/actions/gobgp_action.hpp

src/gobgp_client/gobgp_client.hpp
src/gobgp_client/gobgp_client.cpp

src/bgp_protocol_flow_spec.hpp
src/bgp_protocol_flow_spec.cpp
```

Do not modify additional files unless necessary.

Before editing a file, inspect the actual current contents because line numbers may have changed.

---

## 22. Suggested New Functions

Possible helper:

```text
build_static_test_flowspec_rule()
```

This should construct:

```text
destination = 10.10.10.10/32
protocol = TCP
destination port = 443
```

Possible helper:

```text
build_flowspec_redirect_ipv4_attributes()
```

This should construct the correct Extended Communities attribute for IPv4 redirect.

GoBGP client:

```text
GrpcClient::AddFlowSpecIPv4(...)
```

and:

```text
GrpcClient::DeletePathByUuid(...)
```

Action layer:

```text
gobgp_static_flowspec_test_manage("ban")
gobgp_static_flowspec_test_manage("unban")
```

Exact names are not mandatory.

Follow existing FastNetMon coding conventions.

---

## 23. Implementation Order

Do the work in this order.

### Step 1 — Build static FlowSpec AddPath and unit-test exact wire encoding

Reuse:

```text
flow_spec_rule_t
```

and existing component encoders.

Expected logical rule:

```text
dst 10.10.10.10/32
protocol TCP
dst-port 443
```

Use the resolved `pattrs_binary` set from section 17. Unit-test the exact FlowSpec NLRI, redirect Extended Community, and complete input attribute set before sending the static rule.

### Step 2 — Add GoBGP FlowSpec AddPath method

Construct:

```text
AddPathRequest
```

with:

```text
GLOBAL
AFI 1
SAFI 133
nlri_binary
pattrs_binary
```

Capture the returned UUID.

### Step 3 — Add UUID deletion

Use:

```text
DeletePathRequest.uuid
```

to withdraw the FlowSpec rule.

### Step 4 — Connect to static test ban/unban

Only in explicit test mode.

### Step 5 — Build FastNetMon

Compile the project.

Fix only issues introduced by the MVP changes.

### Step 9 — Test with GoBGP

Verify that GoBGP accepts the AddPath request and advertises the FlowSpec route.

### Step 10 — Test with MX480

Verify:

* BGP session is established
* FlowSpec capability is negotiated
* FlowSpec route is received
* MX480 installs the FlowSpec rule
* only TCP/443 to the specified /32 is redirected
* unrelated traffic is unaffected
* deletion removes the FlowSpec rule

---

## 24. Expected MX480 Test

The first test should use a harmless/discard-only mitigation destination if necessary.

After the FlowSpec control plane is proven, replace the redirect destination with the actual XDP scrubbing server.

The first successful control-plane test is more important than the actual scrubbing implementation.

---

## 25. Production Requirements Later

After the static MVP works, implement:

1. automatic `(protocol, destination port)` classification;
2. confidence threshold;
3. fallback to broader `/32` mitigation when classification is unsafe;
4. multiple simultaneous victims;
5. multiple FlowSpec rules per victim;
6. persistent FlowSpec state;
7. restart reconciliation;
8. recovery after GoBGP restart;
9. duplicate-rule prevention;
10. rule lifecycle tracking;
11. logging and audit information;
12. integration with the existing FastNetMon ban/unban lifecycle;
13. configurable redirect next-hop;
14. potentially IPv6 FlowSpec.

None of these should be implemented before the basic single-rule MVP is proven.

---

## 26. Important Design Principle

The first milestone is NOT:

"Make FastNetMon automatically detect TCP/443 attacks."

The first milestone is:

"Make FastNetMon successfully create, advertise, and withdraw one correct FlowSpec rule through GoBGP to the MX480."

Once that works, the detection/classification problem becomes a separate, much smaller task.

---

## 27. Current State

Architecture analysis is complete enough to begin implementation.

No production code changes have been made yet for this MVP.

The current project already contains:

* GoBGP gRPC client
* FlowSpec structures
* FlowSpec component encoders
* FlowSpec-related extended community structures

The missing part is wiring these pieces together correctly for GoBGP `AddPath` / `DeletePath`.

The GoBGP v3.12.0 `pattrs_binary` requirements for FlowSpec AddPath are resolved in section 17.

The next implementation step is a static FlowSpec `AddPath` plus unit tests for exact wire encoding.

---

## 28. Instructions for Future Codex Sessions

Before doing anything substantial:

1. Read this file completely.
2. Inspect the current git status.
3. Do NOT repeat a full FastNetMon architecture analysis.
4. Do NOT introduce FRR.
5. Do NOT change attack detection logic.
6. Work only on the current MVP unless explicitly instructed otherwise.
7. Prefer small, verifiable changes.
8. After each logical change, build or run the relevant unit test.
9. Do not invent GoBGP wire-format requirements.
10. If something is uncertain, inspect the local vendored GoBGP source first.
11. Keep code comments in English only.
12. Do not make unrelated refactoring changes.

The target architecture remains:

```text
FastNetMon → GoBGP → Juniper MX480 → XDP scrubbing server
```

First concrete target:

```text
10.10.10.10:443/TCP
        |
        v
192.168.100.50
```

with successful FlowSpec advertisement and subsequent withdrawal.
