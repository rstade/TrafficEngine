_**TrafficEngine Overview**_

TrafficEngine is a stateful user-space TCP traffic generator written in Rust with following properties
* high performance: some hundred thousand TCP connections per second (cps) per core. For comparison, modern web servers support some ten thousand cps per core, e.g. https://www.nginx.com/blog/testing-the-performance-of-nginx-and-nginx-plus-web-servers/
* supports client and server TCP roles concurrently
* multi-core, shared nothing, locking-free architecture 
* receive flow steering (RFS) by NIC

It may be used for (load-)testing  TCP based application servers and TCP proxies. TrafficEngine maintains TCP-state and can therefore setup and release complete TCP connections.

Multi-core scaling is supported by steering packets of the same TCP connection based on the TCP port or the IP address to the appropriate core which handles that connection.  Therefore port resources can be assigned to cores (based on paramater _dst_port_mask_ in the configuration file). Alternatively, if the NIC does not support port masks, steering can be based on the IP address.   

TrafficEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking. Starting with version 0.2.0 more generic code is moved to an application independent crate _netfcts_ (in sub-directory netfcts).

_**TrafficEngine Installation**_

First install NetBricks. TrafficEngine needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks. The required NetBricks version is tagged (starting with v0.2.0). Install NetBricks locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml of TrafficEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-rstade/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

The network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)): 

First a network interface for user-space DPDK is needed. This interface is used by the engine to connect to servers (in the example configuration this interface uses PCI slot 07:00.0). The latest code is tested with NIC X520-DA2 (82599).

Secondly an extra Linux interface is required which is used by the test modules for placing server stacks.

For some integration tests both interfaces must be interconnected. In case of physical interfaces, interfaces my be connected by a cross over cable. In case of virtual interfaces, e.g. interfaces may be connected to a host-only network of the hypervisor. Using Wireshark on the linux interface allows us to observe the traffic exchange between clients, the TrafficEngine and the servers. However, as wireshark may not keep up with the transmission speeds of modern line cards, packets may be lost. 

In addition some parameters like the Linux interface name (linux_if) and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted. 

Latest code of TrafficEngine is tested on a 2-socket NUMA server, each socket hosting 4 physical cores, running the real-time kernel of Centos 7.5.

**_Testing_**

The executables must currently be run with supervisor rights, as otherwise the DPDK cannot be initialized. However to avoid that Cargo itself must be run under root, the shell script [test.sh](https://github.com/rstade/TrafficEngine/blob/master/test.sh) can be used, for example 

* "./test.sh test_as_client  --release"  or  "./test.sh test_as_server  --release". 

The script requires installation of the _jq_ tool, e.g.  by running "yum install jq". 

In addition the script allows to run a simple loopback helper tool, called macswap:
* "./test.sh macswap --release"

This tool can be used in cases the loopback mode of the NIC is not working. This happened with X710DA2. The tool should be run ideally on a second server. It swaps source and destination MAC addresses and sends the frames back towards the origin. 


**_Performance_**

Our test scenario is as follows:

* We connect client- with server-side of TrafficEngine by using the loopback feature of the NIC (see [loopback_run.toml](https://github.com/rstade/TrafficEngine/blob/master/loopback_run.toml)). For this we used a 82599 based NIC.
* After the client has setup the TCP connection, it sends a small payload packet to the server. After receiving the payload the server side release the TCP connection. In total we exchange seven packets per connection. 
* The same TrafficEngine instance operates concurrently as client and as server. Therefore when comparing our cps figures with the cps of a TCP server our figures can be approximately doubled. 
* Tests were run on a two socket server with two rather old 4 core L5520 CPU @ 2.27GHz with 32K/256K/8192K L1/L2/L3 Cache and a recent Centos 7.5 real-time kernel, e.g. from repository:  http://linuxsoft.cern.ch/cern/centos/7/rt/CentOS-RT.repo. We also performed the basic tuning steps to isolate the cores which are running our working threads. The real-time kernel increases determinism significantly versus the usual Centos non-real-time kernel. For more information see [rt-tuning.md](https://github.com/rstade/TrafficEngine/blob/master/rt-tuning.md).
* Each test run sets up and releases 48000 connections per pipeline.

The following figures shows first results for the achieved connections per second in dependence of the used cores.

![TrafficEngine performance](https://github.com/rstade/trafficengine/blob/master/cps_vs_cores.png)

**_Limitations_**

Currently only a basic TCP state machine without retransmission, flow control, etc., is implemented.







