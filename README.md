_**ProxyEngine Overview**_

ProxyEngine is a user-space TCP-proxy written in Rust with following properties
* TCP pass-through
* customizable delayed binding
* high performance: multi-core, shared nothing, locking-free architecture
* client side receive side scaling (RSS), server side receive flow steering (RFS) by NIC
* customizable payload inspection and manipulation

It may be used for intelligent load-balancing and fire-walling of TCP based protocols, e.g. LDAP. Late binding allows to select the target server not till the first payload packet after the initial three-way hand-shake is received. In addition callbacks can be defined by which the proxy can modify the payload of the TCP based protocol. For this purpose additional connection state is maintained by the ProxyEngine.

First benchmarking shows that ProxyEngine can forward about 1.3 million packets per second per physical core (of a rather old 4 core L5520 CPU @ 2.27GHz with 32K/256K/8192K L1/L2/L3 Cache). Do not forget to compile with --release flag for any benchmarking ;-)

Scaling happens by distributing incoming client-side TCP connections using RSS over the cores and by steering the incoming server side TCP connections to the appropriate core based on the selected server side proxy-port. Therefore server-side port resources are assigned to cores (based on paramater _dst_port_mask_ in the configuration file).    

ProxyEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking.

_**ProxyEngine Installation**_

First install NetBricks. ProxyEngine needs the branch e2d2-0-1-1 from the fork at https://github.com/rstade/Netbricks. Often there has been a commit of the NetBricks fork together with that of ProxyEngine. Install the branch locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml for the ProxyEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-0-1-1/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

ProxyEngine includes a main program bin.rs (using example configurations _\*.toml_) and test modules (using configurations _tests/\*.toml_). For both the network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)). 

First a network interface for user-space DPDK is needed. This interface is used by the proxy to connect to clients and servers (in the example configuration this interface uses PCI slot 07:00.0). The latest code is tested with NIC X520-DA2 (82599) and previous single rx/tx versions with e1000e and vmxnet3.

Secondly an extra Linux interface is required which is used by the test modules for placing client and server stacks.

Both interfaces must be interconnected. In case of virtual interfaces, e.g. interfaces may be connected to a host-only network of the hypervisor. Using Wireshark on this network allows us to observe the complete traffic exchange between clients, the proxy and the servers. In case of physical interfaces, interfaces my be connected by a cross over cable.

In addition some parameters like the Linux interface name (linux_if) and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted. 

Latest code of ProxyEngine is tested on a 2-socket NUMA server, each socket hosting 4 physical cores, running Centos 7.4. The benchmarking mentioned above was done with two servers, one running iperf3 client and server instances, the other running the ProxyEngine as the device under test (DUT). More benchmarking to follow.


_**ProxyEngine Test Configuration**_

![proxyengine test configuration](https://github.com/silverengine-de/proxyengine/blob/master/proxyengine_config.png)
