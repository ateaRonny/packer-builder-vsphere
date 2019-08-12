[![Team project](http://jb.gg/badges/team.svg)](https://confluence.jetbrains.com/display/ALL/JetBrains+on+GitHub)
[![GitHub latest release](https://img.shields.io/github/release/jetbrains-infra/packer-builder-vsphere.svg)](https://github.com/jetbrains-infra/packer-builder-vsphere/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/jetbrains-infra/packer-builder-vsphere/total.svg)](https://github.com/jetbrains-infra/packer-builder-vsphere/releases)
[![TeamCity build status](https://img.shields.io/teamcity/http/teamcity.jetbrains.com/s/PackerVSphere_Build.svg)](https://teamcity.jetbrains.com/viewType.html?buildTypeId=PackerVSphere_Build&guest=1)


# Packer Builder for VMware vSphere

This a plugin for [HashiCorp Packer](https://www.packer.io/). It uses native vSphere API, and creates virtual machines remotely.

`vsphere-iso` builder creates new VMs from scratch.
`vsphere-clone` builder clones VMs from existing templates.

- VMware Player is not required.
- Official vCenter API is used, no ESXi host [modification](https://www.packer.io/docs/builders/vmware-iso.html#building-on-a-remote-vsphere-hypervisor) is required.

## Installation
* Download binaries from the [releases page](https://github.com/jetbrains-infra/packer-builder-vsphere/releases).
* [Install](https://www.packer.io/docs/extending/plugins.html#installing-plugins) the plugins, or simply put them into the same directory with JSON templates. On Linux and macOS run `chmod +x` on the files.

## Build

Install Go and [dep](https://github.com/golang/dep/releases), run `build.sh`.

Or build inside a container by Docker Compose:
```
docker-compose run build
```

The binaries will be in `bin/` directory.

Artifacts can be also downloaded from [TeamCity builds](https://teamcity.jetbrains.com/viewLog.html?buildTypeId=PackerVSphere_Build&buildId=lastSuccessful&tab=artifacts&guest=1).

## Examples

See complete Ubuntu, Windows, and macOS templates in the [examples folder](https://github.com/jetbrains-infra/packer-builder-vsphere/tree/master/examples/).

## Parameter Reference

### Connection

* `vcenter_server`(string) - vCenter server hostname.
* `username`(string) - vSphere username.
* `password`(string) - vSphere password.
* `insecure_connection`(boolean) - Do not validate vCenter server's TLS certificate. Defaults to `false`.
* `datacenter`(string) - VMware datacenter name. Required if there is more than one datacenter in vCenter.
* `persist`(boolean) - Load existing govmomi session from disk. Also save to disk.
* `vimsessionpath`(string) - The directory where govmomi session is loaded from and saved to. Default: ${HOME}/.govmomi/sessions

### VM Location

* `vm_name`(string) - Name of the new VM to create.
* `folder`(string) - VM folder to create the VM in.
* `host`(string) - ESXi host where target VM is created. A full path must be specified if the host is in a folder. For example `folder/host`. See the `Specifying Clusters and Hosts` section above for more details.
* `cluster`(string)  - ESXi cluster where target VM is created. See [Working with Clusters](#working-with-clusters).
* `resource_pool`(string) - VMWare resource pool. Defaults to the root resource pool of the `host` or `cluster`.
* `datastore`(string) - VMWare datastore. Required if `host` is a cluster, or if `host` has multiple datastores.
* `notes`(string) - VM notes.

### VM Location (`vsphere-clone` only)

* `template`(string) - Name of source VM. Path is optional.
* `linked_clone`(boolean) - Create VM as a linked clone from latest snapshot. Defaults to `false`.

### Hardware

* `CPUs`(number) - Number of CPU sockets.
* `cpu_cores`(number) - Number of CPU cores per socket.
* `CPU_limit`(number) - Upper limit of available CPU resources in MHz.
* `CPU_reservation`(number) - Amount of reserved CPU resources in MHz.
* `CPU_hot_plug`(boolean) - Enable CPU hot plug setting for virtual machine. Defaults to `false`.
* `RAM`(number) - Amount of RAM in MB.
* `RAM_reservation`(number) - Amount of reserved RAM in MB.
* `RAM_reserve_all`(boolean) - Reserve all available RAM. Defaults to `false`. Cannot be used together with `RAM_reservation`.
* `RAM_hot_plug`(boolean) - Enable RAM hot plug setting for virtual machine. Defaults to `false`.
* `video_ram`(number) - Amount of video memory in MB.
* `disk_size`(number) - The size of the disk in MB.
* `network`(string) - Set network VM will be connected to.
* `NestedHV`(boolean) - Enable nested hardware virtualization for VM. Defaults to `false`.
* `configuration_parameters`(map) - Custom parameters.
* `boot_order`(string) - Priority of boot devices. Defaults to `disk,cdrom`

### Hardware (`vsphere-iso` only)

* `vm_version`(number) - Set VM hardware version. Defaults to the most current VM hardware version supported by vCenter. See [VMWare article 1003746](https://kb.vmware.com/s/article/1003746) for the full list of supported VM hardware versions.
* `guest_os_type`(string) - Set VM OS type. Defaults to `otherGuest`. See [here](https://pubs.vmware.com/vsphere-6-5/index.jsp?topic=%2Fcom.vmware.wssdk.apiref.doc%2Fvim.vm.GuestOsDescriptor.GuestOsIdentifier.html) for a full list of possible values.
* `disk_controller_type`(string) - Set VM disk controller type. Example `pvscsi`.
* `disk_thin_provisioned`(boolean) - Enable VMDK thin provisioning for VM. Defaults to `false`.
* `network_card`(string) - Set VM network card type. Example `vmxnet3`.
* `usb_controller`(boolean) - Create USB controller for virtual machine. Defaults to `false`.
* `cdrom_type`(string) - Which controller to use. Example `sata`. Defaults to `ide`.
* `firmware`(string) - Set the Firmware at machine creation. Example `efi`. Defaults to `bios`.


### Boot (`vsphere-iso` only)

* `iso_paths`(array of strings) - List of datastore paths to ISO files that will be mounted to the VM. Example `"[datastore1] ISO/ubuntu.iso"`.
* `floppy_files`(array of strings) - List of local files to be mounted to the VM floppy drive. Can be used to make Debian preseed or RHEL kickstart files available to the VM.
* `floppy_dirs`(array of strings) - List of directories to copy files from.
* `floppy_img_path`(string) - Datastore path to a floppy image that will be mounted to the VM. Example `[datastore1] ISO/pvscsi-Windows8.flp`.
* `http_directory`(string) - Path to a directory to serve using a local HTTP server. Beware of [limitations](https://github.com/jetbrains-infra/packer-builder-vsphere/issues/108#issuecomment-449634324).
* `http_ip`(string) - Specify IP address on which the HTTP server is started. If not provided the first non-loopback interface is used.
* `http_port_min` and `http_port_max` as in other [builders](https://www.packer.io/docs/builders/virtualbox-iso.html#http_port_min).
* `iso_urls`(array of strings) - Multiple URLs for the ISO to download. Packer will try these in order. If anything goes wrong attempting to download or while downloading a single URL, it will move on to the next. All URLs must point to the same file (same checksum). By default this is empty and iso_url is used. Only one of iso_url or iso_urls can be specified.
* `iso_checksum `(string) - The checksum for the OS ISO file. Because ISO files are so large, this is required and Packer will verify it prior to booting a virtual machine with the ISO attached. The type of the checksum is specified with iso_checksum_type, documented below. At least one of iso_checksum and iso_checksum_url must be defined. This has precedence over iso_checksum_url type.
* `iso_checksum_type`(string) - The type of the checksum specified in iso_checksum. Valid values are none, md5, sha1, sha256, or sha512 currently. While none will skip checksumming, this is not recommended since ISO files are generally large and corruption does happen from time to time.
* `iso_checksum_url`(string) -  A URL to a GNU or BSD style checksum file containing a checksum for the OS ISO file. At least one of iso_checksum and iso_checksum_url must be defined. This will be ignored if iso_checksum is non empty.
* `boot_wait`(string) Amount of time to wait for the VM to boot. Examples 45s and 10m. Defaults to 10 seconds. See [format](https://golang.org/pkg/time/#ParseDuration).
* `boot_command`(array of strings) - List of commands to type when the VM is first booted. Used to initalize the operating system installer. See details in [Packer docs](https://www.packer.io/docs/builders/virtualbox-iso.html#boot-command).

### Provision

* `communicator` - `ssh` (default), `winrm`, or `none` (create/clone, customize hardware, but do not boot).
* `ip_wait_timeout`(string) - Amount of time to wait for VM's IP, similar to 'ssh_timeout'. Defaults to 30m (30 minutes). See the Go Lang [ParseDuration](https://golang.org/pkg/time/#ParseDuration) documentation for full details.
* `ip_settle_timeout`(string) - Amount of time to wait for VM's IP to settle down, sometimes VM may report incorrect IP initially, then its recommended to set that parameter to apx. 2 minutes. Examples 45s and 10m. Defaults to 5s(5 seconds). See the Go Lang [ParseDuration](https://golang.org/pkg/time/#ParseDuration) documentation for full details.
* `ssh_username`(string) - Username in guest OS.
* `ssh_password`(string) - Password to access guest OS. Only specify `ssh_password` or `ssh_private_key_file`, but not both.
* `ssh_private_key_file`(string) - Path to the SSH private key file to access guest OS. Only specify `ssh_password` or `ssh_private_key_file`, but not both.
* `winrm_username`(string) - Username in guest OS.
* `winrm_password`(string) - Password to access guest OS.
* `shutdown_command`(string) - Specify a VM guest shutdown command. VMware guest tools are used by default.
* `shutdown_timeout`(string) - Amount of time to wait for graceful VM shutdown. Examples 45s and 10m. Defaults to 5m(5 minutes). See the Go Lang [ParseDuration](https://golang.org/pkg/time/#ParseDuration) documentation for full details.

### Postprocessing

* `create_snapshot`(boolean) - Create a snapshot when set to `true`, so the VM can be used as a base for linked clones. Defaults to `false`.
* `convert_to_template`(boolean) - Convert VM to a template. Defaults to `false`.

## Working with Clusters
#### Standalone Hosts
Only use the `host` option. Optionally specify a `resource_pool`:
```
"host": "esxi-1.vsphere65.test",
"resource_pool": "pool1",
```

#### Clusters Without DRS
Use the `cluster` and `host `parameters:
```
"cluster": "cluster1",
"host": "esxi-2.vsphere65.test",
```

#### Clusters With DRS
Only use the `cluster` option. Optionally specify a `resource_pool`:
```
"cluster": "cluster2",
"resource_pool": "pool1",
```

## Required vSphere Permissions

* VM folder (this object and children):
    ```
    Virtual machine -> Inventory
    Virtual machine -> Configuration
    Virtual machine -> Interaction
    Virtual machine -> Snapshot management
    Virtual machine -> Provisioning
    ```
    Individual privileges are listed in https://github.com/jetbrains-infra/packer-builder-vsphere/issues/97#issuecomment-436063235.
* Resource pool, host, or cluster (this object): 
    ```
    Resource -> Assign virtual machine to resource pool
    ```
* Host in clusters without DRS (this object): 
    ```
    Read-only
    ```
* Datastore (this object): 
    ```
    Datastore -> Allocate space
    Datastore -> Browse datastore
    Datastore -> Low level file operations
    ```  
* Network (this object): 
    ```
    Network -> Assign network
    ```
* Distributed switch (this object): 
    ```
    Read-only
    ```

For floppy image upload:

* Datacenter (this object): 
    ```
    Datastore -> Low level file operations
    ```
* Host (this object): 
    ```
    Host -> Configuration -> System Management
    ```
