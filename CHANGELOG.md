##CHANGELOG

## v1.0.0
* move to frankspeech repo


## v0.3.8
* Update Vault, Nomad and Consul versions to latest

## v0.3.7
* Add support for Vault server Ansible role vars

## v0.3.6
* Add bootstrapping vars to support Consul servers
* Pass in tags to VM module
* Update Consul cloud autodiscovery string building

## v0.3.5
* adding docker_vault_login and vault_docker_secrets vars
* Updating the nomad_acl_enabled default value to "yes"

## v0.3.2
* Adding known hosts ansible extra vars for known_hosts role

## v0.3.1
* Bump Consul to version 1.11.1
* Bump Vault Agent to version 1.9.2
* Add vars for configuring dnsmasq with Consul Ansible role

## v0.3.0
* Adding in nomad_plugins to ansible args

## v0.2.8
* Bump Vault, Nomad and Consul versions to 1.9.1, 1.2.3, and 1.10.4, respectively

## v0.2.7
* Add var to VM module call for Consul node metadata

## v0.2.6
* Adding s3 extra options flag

## v0.2.5
* Add vars to VM module call for Nomad telemetry

## v0.2.4
* Enable Nomad alloc and node metrics by default

## v0.2.3
* Doubled default Prometheus metrics retention time for Consul

## v0.2.2
* Enable Consul telemetry by default via Consul custom config

## v0.2.1
* Bump Nomad default version to 1.2.2
* Add support for Consul custom config passed to playbook run

## v0.2.0
* Bump Nomad default version to 1.2.0
* Bump Vault agent default version to 1.9.0

## v0.1.19
* Decoupled memory size and # of cores into separate vars; removed resource pool type

## v0.1.18
* Fix disk size type validation

## v0.1.17
* Add VM sizes xxxl and xxxxl to support sizing requirements for Wowza project.

## v0.1.16
* Decoupled disk size from CPU/memory into separately managed size grouping "disk_size_type"
* Added nano and micro size types
* Updated size types to match T2 AWS EC2 sizings

## v0.1.15
* Add support for xxl resource pool

## v0.1.13
* Bump default versions of Consul, Nomad and Vault to 1.10.3, 1.1.6, and 1.8.4, respectively

## v0.1.12
* Add support for passing in Consul ACL default token to provisioner
* Add support for passing in Consul ACL token for Nomad configuration to provisioner

## v0.1.8
* Update default iptables configuration for Consul to False

## v0.1.7
* Update default port for Docker daemon metrics

## v0.1.6
* Enable Docker daemon metrics by default via docker_daemon_options variable

## v0.1.5
* Update consul_addresses_http default value to include localhost as well as the bind address of the machine, determined by the role

## v0.1.4
* Fix Docker daemon options default value syntax
* Update main to pass in consul_addresses_http var to VM module

## v0.1.3
* Add var for customizable Docker daemon configurations
* Add var for customizable Consul HTTP address configuration
* Set default Nomad user/group to root/bin
* Set default creation of user and group "nomad" to false