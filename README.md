_**TrafficEngine Overview**_

TrafficEngine is a stateful user-space TCP traffic generator written in Rust with following properties
* high performance: some hundred thousand TCP connections per second (cps) per core). For comparison, modern web servers support some ten thousand cps per core, e.g. https://www.nginx.com/blog/testing-the-performance-of-nginx-and-nginx-plus-web-servers/
* multi-core, shared nothing, locking-free architecture 
* server side receive flow steering (RFS) by NIC

It may be used for (load-)testing  TCP based application servers and TCP proxies. TrafficEngine maintains TCP-state and can therefore setup and release complete TCP connections.

Scaling happens by steering the incoming server side TCP connections based on the TCP port to the appropriate core which handles the connection.  Therefore port resources are assigned to cores (based on paramater _dst_port_mask_ in the configuration file).    

TrafficEngine builds on [Netbricks](https://github.com/NetSys/NetBricks) which itself utilizes DPDK for user-space networking. Starting with version 0.2.0 more generic code is moved to an application independent crate _netfcts_ (in sub-directory netfcts).

_**TrafficEngine Installation**_

First install NetBricks. TrafficEngine needs the branch e2d2-rstade from the fork at https://github.com/rstade/Netbricks. The required NetBricks version is tagged (starting with v0.2.0). Install NetBricks locally on your (virtual) machine by following the description of NetBricks. The (relative) installation path of e2d2 needs to be updated in the dependency section of Cargo.toml of TrafficEngine. 

Note, that a local installation of NetBricks is necessary as it includes DPDK and some C-libraries for interfacing the Rust code of NetBricks with the DPDK. As we need DPDK kernel modules, DPDK needs to be re-compiled each time the kernel version changes. This can be done with the script [build.sh](https://github.com/rstade/NetBricks/blob/e2d2-rstade/build.sh) of NetBricks. Note also that the Linux linker _ld_ needs to be made aware of the location of the .so libraries created by NetBricks. This can be solved using _ldconfig_.

The network interfaces of the test machine need to be prepared (see [prepNet.sh](https://github.com/silverengine-de/proxyengine/blob/master/prepNet.sh)): 

First a network interface for user-space DPDK is needed. This interface is used by the engine to connect to servers (in the example configuration this interface uses PCI slot 07:00.0). The latest code is tested with NIC X520-DA2 (82599).

Secondly an extra Linux interface is required which is used by the test modules for placing server stacks.

For integration testing both interfaces must be interconnected. In case of virtual interfaces, e.g. interfaces may be connected to a host-only network of the hypervisor. Using Wireshark on this network allows us to observe the traffic exchange between clients, the proxy and the servers. However, as wireshark may not keep up with the transmission speeds of modern line cards, packets may be lost. In case of physical interfaces, interfaces my be connected by a cross over cable.

In addition some parameters like the Linux interface name (linux_if) and the IP / MAC addresses in the test module configuration files  tests/*.toml need to be adapted. 

Latest code of TrafficEngine is tested on a 2-socket NUMA server, each socket hosting 4 physical cores, running Centos 7.5.


