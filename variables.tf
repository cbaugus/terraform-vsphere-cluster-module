variable "num_instances" {
  description = "Number of VMs to provision"
  default     = "1"
  type        = string
}
variable "name_prefix" {
  description = "Prefix for naming convention of VMs"
  default     = "vm"
  type        = string
}
variable "cores_count_type" {
  description = "Nano, micro, mmall, medium, large, xl or xxl count of cores."
  default     = "small"
  type        = string
  validation {
    condition     = var.cores_count_type == "nano" || var.cores_count_type == "micro" || var.cores_count_type == "small" || var.cores_count_type == "medium" || var.cores_count_type == "large" || var.cores_count_type == "xl" || var.cores_count_type == "xxl" || var.cores_count_type == "xxxl" || var.cores_count_type == "xxxxl"
    error_message = "Cores count must be nano, micro, small, medium, large, xl or xxl."
  }
}
variable "num_cores" {
  description = "Number of CPUs for VMs in cluster"
  default = {
    nano   = 1
    micro  = 1
    small  = 1
    medium = 2
    large  = 2
    xl     = 4
    xxl    = 8
    xxxl   = 16
    xxxxl  = 32
  }
}
variable "mem_size_type" {
  description = "Nano, micro, mmall, medium, large, xl or xxl memory size."
  default     = "small"
  type        = string
  validation {
    condition     = var.mem_size_type == "nano" || var.mem_size_type == "micro" || var.mem_size_type == "small" || var.mem_size_type == "medium" || var.mem_size_type == "large" || var.mem_size_type == "xl" || var.mem_size_type == "xxl" || var.mem_size_type == "xxxl" || var.mem_size_type == "xxxxl"
    error_message = "Memory size type must be nano, micro, small, medium, large, xl or xxl."
  }
}
variable "mem_size" {
  description = "Amount of memory to be applied to VM(s)"
  default = {
    nano   = "512"
    micro  = "1024"
    small  = "2048"
    medium = "4096"
    large  = "8192"
    xl     = "16384"
    xxl    = "32768"
    xxxl   = "65536"
    xxxxl  = "131072"
  }
}
variable "disk_size_type" {
  description = "Nano, micro, mmall, medium, large, xl or xxl disk size."
  default     = "small"
  type        = string
  validation {
    condition     = var.disk_size_type == "nano" || var.disk_size_type == "micro" || var.disk_size_type == "small" || var.disk_size_type == "medium" || var.disk_size_type == "large" || var.disk_size_type == "xl" || var.disk_size_type == "xxl"
    error_message = "Disk size type must be nano, micro, small, medium, large, xl or xxl."
  }
}
variable "disk_size" {
  description = "Size of drive (GB) to be applied to VM(s)"
  default = {
    nano   = 10
    micro  = 20
    small  = 35
    medium = 70
    large  = 120
    xl     = 240
    xxl    = 480
  }
}
variable "ip_address" {
  description = "IP address to use on one network"
  type        = string
  default     = ""
}
variable "ip_addresses" {
  description = "IP addresses of VMs to create, empty string for DHCP"
  type        = list(string)
  default     = null
}
#### vSphere Vars ####
variable "vsphere_user" {
  description = "vSphere administrator username"
  type        = string
  default     = "terraform-vsphere@vsphere.local"
  sensitive   = true
}
variable "vsphere_pass" {
  description = "vSphere administrator password"
  type        = string
  default     = ""
  sensitive   = true
}
variable "vsphere_server" {
  description = "vSphere server address"
  type        = string
  default     = "10.254.101.20"
  sensitive   = true
}
variable "vsphere_datacenter" {
  description = "vSphere datacenter"
  default     = "tmi-w01-dc01"
  type        = string
}
variable "vsphere_compute_cluster" {
  description = "vSphere compute cluster"
  default     = "tmi-w01-cl01-dev"
  type        = string
}
variable "vsphere_resource_pool" {
  description = "vSphere resource pool"
  default     = "tmi-w01-dc01/tmi-w01-cl01/Resources"
  type        = string
}
variable "vsphere_datastore" {
  description = "vSphere datastore"
  default     = "troy-nonprod-ds-vsan"
  type        = string
}
variable "vsphere_network" {
  description = "vSphere network"
  default     = "tmi-w01-cl01-vds01-pg-ops-203"
  type        = string
}
##TODO: Determine default folder
variable "vsphere_folder" {
  description = "vSphere folder"
  type        = string
  default     = "feature"
}
variable "vsphere_template" {
  description = "vSphere template for creating VM"
  default     = "linux-ubuntu-server-20-04-lts-tmi-w01-cl01-dev"
  type        = string
}
variable "vsphere_tag_ids" {
  description = "Tag IDs to apply to the VMs"
  default     = []
  type        = list(string)
}
##TODO: Determine default provisioned disks
variable "provisioned_disks" {
  description = "Storage data disk parameter, example"
  type        = any
  default     = {}
}
##TODO: Determine default S3 provisioned disks
variable "s3_provisioned_disks" {
  description = "Storage data disk parameter, holding paramaters for provisioning with s3_handlr ansible role"
  type        = any
  default     = {}
}
variable "growr_provisioned_disks" {
  description = "Storage data disk parameter, holding paramaters for provisioning with growr ansible role"
  type        = any
  default     = {}
}
variable "remote_exec_command" {
  description = "Command for remote exec provisioner to run"
  type        = string
  default     = "echo Running the remote-exec provisioner"
}
variable "remote_exec_user" {
  description = "User for remote exec provisioner to connect as"
  type        = string
  default     = "cicduser"
}
variable "remote_exec_ssh_key_file" {
  description = "Path to the SSH key to connect to created VMs, located on the Terraform runner"
  type        = string
  default     = "/opt/devops-local/ssh/cicduser"
}
variable "remote_exec_timeout" {
  description = "Timeout value for remote exec provisioner to connect to VM"
  type        = string
  default     = "1m"
}
variable "local_exec_user" {
  description = "User for local exec provisioner to connect as with Ansible"
  type        = string
  default     = "cicduser"
}
variable "local_exec_ssh_key_file" {
  description = "Path to the SSH key to connect to created VMs, located on the Terraform runner"
  type        = string
  default     = "/opt/devops-local/ssh/cicduser"
}
variable "path_to_ansible" {
  description = "Location of Ansible playbook on Terraform runner"
  type        = string
  default     = "../../ansible-deployments/main.yml"
}
##TODO: Determine if this is needed
variable "provisioner_hostname_flag" {
  description = "Flag to indicate if the two variables hostname and nomad_node_name should be supplied to the local-exec provisioner with the VM name"
  type        = string
  default     = "true"
  validation {
    condition     = var.provisioner_hostname_flag == "true" || var.provisioner_hostname_flag == "false"
    error_message = "Variable provisioner_hostname_flag must be true or false."
  }
}
variable "ansible_python_interpreter" {
  description = "Python interpreter to be used on target machine"
  type        = string
  default     = "/usr/bin/python3"
}
variable "consul_user" {
  description = "vSphere Consul username"
  type        = string
  sensitive   = true
  default     = "consul"
}
variable "consul_manage_user" {
  description = "Whether to create the user defined by consul_user or not"
  type        = string
  sensitive   = true
  default     = "True"
}
variable "consul_group" {
  description = "Group for Consul"
  type        = string
  default     = "consul"
}
variable "consul_manage_group" {
  description = "Whether to create the group defined by consul_group or not"
  type        = string
  default     = "true"
}
variable "consul_group_name" {
  description = "Group name for Consul"
  type        = string
  default     = "all"
}
variable "consul_pass" {
  description = "vSphere Consul password"
  type        = string
  sensitive   = true
  default     = ""
}
variable "consul_domain" {
  description = "Domain for Consul DNS"
  type        = string
  default     = "consul."
}
variable "consul_node_meta" {
  description = "Consul node meta data (key-value)"
  type        = map(string)
  default     = {}
}
variable "consul_cloud_autodiscovery" {
  description = "Consul cloud auto discovery enabled/disabled flag"
  type        = string
  default     = "True"
}
variable "consul_cloud_autodiscovery_tag_category" {
  description = "VMware VM tag category to use in Consul cloud auto discovery string"
  type        = string
  default     = "vmTags"
}
variable "consul_cloud_autodiscovery_tag_name" {
  description = "VMware VM tag name to use in Consul cloud auto discovery string"
  type        = string
  default     = "consul"
}
## TLS Vars ##
variable "consul_tls_enable" {
  description = "Consul gossip key"
  type        = string
  sensitive   = true
  default     = "True"
}
variable "consul_tls_ca_crt" {
  description = "Consul CA certificate file name"
  type        = string
  sensitive   = true
  default     = "consul-agent-ca.pem"
}
variable "consul_tls_server_crt" {
  description = "Consul CA Server certificate file name"
  type        = string
  sensitive   = true
  default     = ""
}
variable "consul_tls_server_key" {
  description = "Consul CA Server Key file name"
  type        = string
  sensitive   = true
  default     = ""
}
variable "consul_src_def" {
  description = "Default source directory for TLS files"
  type        = string
  default     = "/opt/devops-local/ssl/certs"
}
variable "consul_tls_src_files" {
  description = "User-specified source directory for TLS files"
  type        = string
  default     = "/opt/devops-local/ssl/certs"
}
variable "consul_tls_verify_incoming" {
  description = "Verify incoming Gossip connections"
  type        = string
  default     = "False"
}
variable "consul_tls_verify_outgoing" {
  description = "Verify outgoing Gossip connections"
  type        = string
  default     = "True"
}
variable "consul_tls_verify_server_hostname" {
  description = "Verify server hostname"
  type        = string
  default     = "True"
}
variable "consul_tls_min_version" {
  description = "Minimum acceptable TLS version"
  type        = string
  default     = "tls12"
}
variable "consul_tls_cipher_suites" {
  description = "Comma-separated list of supported ciphersuites"
  type        = string
  default     = ""
}
variable "consul_tls_prefer_server_cipher_suites" {
  description = "Prefer server's cipher suite over client cipher suite"
  type        = string
  default     = ""
}
variable "auto_encrypt" {
  description = "auto_encrypt"
  type        = map(any)
  default     = { "enabled" = "True" }
}
##TODO: Determine if should be True
variable "consul_tls_verify_incoming_rpc" {
  description = "Verify incoming connections on RPC endpoints (client certificates)"
  type        = string
  default     = "False"
}
##TODO: Determine if should be True
variable "consul_tls_verify_incoming_https" {
  description = "Verify incoming connections on HTTPS endpoints (client certificates)"
  type        = string
  default     = "False"
}
## Encrypt Vars ##
variable "consul_encrypt_enable" {
  description = "Enable Gossip Encryption"
  type        = string
  default     = "True"
}
variable "consul_encrypt_verify_incoming" {
  description = "Verify incoming Gossip connections"
  type        = string
  default     = "True"
}
variable "consul_encrypt_verify_outgoing" {
  description = "Verify outgoing Gossip connections"
  type        = string
  default     = "True"
}
variable "consul_disable_keyring_file" {
  description = "If set, the keyring will not be persisted to a file. Any installed keys will be lost on shutdown, and only the given -encrypt key will be available on startup."
  type        = string
  default     = "False"
}
##TODO: Source from Vault?
variable "consul_raw_key" {
  description = "Consul gossip key"
  type        = string
  sensitive   = true
  default     = ""
}
variable "consul_node_role" {
  description = "The Consul role of the node, one of: bootstrap, server, or client"
  type        = string
  default     = "client"
}
variable "consul_bootstrap_expect" {
  description = "Boolean that adds bootstrap_expect value on Consul servers's config file"
  type        = string
  default     = "false"
}
variable "consul_bootstrap_expect_value" {
  description = "Integer to define the minimum number of consul servers joined to the cluster in order to elect the leader"
  type        = number
  default     = 3
}
variable "consul_connect_enabled" {
  description = "Enable Consul Connect feature"
  type        = string
  default     = "True"
}
variable "consul_syslog_enable" {
  description = "Log to syslog as defined in enable_syslog or -syslog"
  type        = string
  default     = "True"
}
variable "consul_install_remotely" {
  description = "Whether to download the files for installation directly on the remote hosts"
  type        = string
  default     = "False"
}
variable "consul_install_upgrade" {
  description = "Whether to upgrade consul when a new version is specified"
  type        = string
  default     = "False"
}
variable "consul_ui" {
  description = "Enable the consul ui"
  type        = string
  default     = "True"
}
variable "consul_ui_legacy" {
  description = "Enable legacy consul ui mode"
  type        = string
  default     = "False"
}
variable "consul_disable_update_check" {
  description = "Disable the consul update check"
  type        = string
  default     = "False"
}
variable "consul_enable_script_checks" {
  description = "Enable script based checks"
  type        = string
  default     = "True"
}
variable "consul_enable_local_script_checks" {
  description = "Enable script based checks"
  type        = number
  default     = 3
}
variable "consul_raft_protocol" {
  description = "Raft protocol to use"
  type        = string
  default     = "3"
}
variable "consul_version" {
  description = "Version to install"
  type        = string
  default     = "1.11.4"
}
//variable "consul_architecture_map" {
//  description = "Dictionary for translating ansible_architecture values to Go architecture values naming convention"
//  type = string
//  default = "dict"
//}
//variable "consul_architecture" {
//  description = "System architecture as determined by {{ consul_architecture_map[ansible_architecture] }}"
//  type = string
//  default = "amd64"
//}
variable "consul_bin_path" {
  description = "Binary installation path"
  type        = string
  default     = "/usr/local/bin"
}
variable "consul_config_path" {
  description = "Base configuration file path"
  type        = string
  default     = "/etc/consul"
}
variable "consul_data_path" {
  description = "Data directory path as defined in data_dir or -data-dir"
  type        = string
  default     = "/var/consul"
}
variable "consul_configure_syslogd" {
  description = "Enable configuration of rsyslogd or syslog-ng on Linux. If disabled, Consul will still log to syslog if consul_syslog_enable is true, but the syslog daemon won't be configured to write Consul logs to their own logfile"
  type        = string
  default     = "False"
}
##TODO: Determine if defaults should be set for log path and log file
variable "consul_log_path" {
  description = ""
  type        = string
  default     = "/var/log/consul"
}
variable "consul_log_file" {
  description = ""
  type        = string
  default     = "consul.log"
}
variable "consul_log_level" {
  description = "Log level as defined in log_level or -log-level"
  type        = string
  default     = "INFO"
}
variable "consul_log_rotate_bytes" {
  description = "Log rotate bytes as defined in log_rotate_bytes or -log-rotate-bytes"
  type        = number
  default     = 0
}
variable "consul_log_rotate_duration" {
  description = "Log rotate bytes as defined in log_rotate_duration or -log-rotate-duration"
  type        = string
  default     = "24h"
}
variable "consul_log_rotate_max_files" {
  description = "Log rotate bytes as defined in log_rotate_max_files or -log-rotate-max-files"
  type        = number
  default     = 0
}
variable "consul_syslog_facility" {
  description = "Syslog facility as defined in syslog_facility"
  type        = string
  default     = "local0"
}
variable "syslog_user" {
  description = "Owner of rsyslogd process on Linux. consul_log_path's ownership is set to this user on Linux. Ignored if consul_configure_syslogd is false"
  type        = string
  default     = "syslog"
}
variable "syslog_group" {
  description = "Group of user running rsyslogd process on Linux. consul_log_path's group ownership is set to this group on Linux. Ignored if consul_configure_syslogd is false"
  type        = string
  default     = "adm"
}
variable "consul_run_path" {
  description = "Run path for process identifier (PID) file"
  type        = string
  default     = "/run/consul"
}
variable "consul_retry_interval" {
  description = "Interval for reconnection attempts to LAN servers"
  type        = string
  default     = "30s"
}
variable "consul_retry_interval_wan" {
  description = "Interval for reconnection attempts to WAN servers"
  type        = string
  default     = "30s"
}
variable "consul_retry_join_skip_hosts" {
  description = "If true, the config value for retry_join won't be populated by the default hosts servers. The value can be initialized using consul_join"
  type        = string
  default     = "False"
}
variable "consul_retry_max" {
  description = "Max reconnection attempts to LAN servers before failing (0 = infinite)"
  type        = number
  default     = 0
}
variable "consul_retry_max_wan" {
  description = "Max reconnection attempts to WAN servers before failing (0 = infinite)"
  type        = number
  default     = 0
}
## ACL Vars ##
variable "consul_acl_enable" {
  description = "Enable ACLs"
  type        = string
  default     = "True"
}
variable "consul_acl_token" {
  description = "Default ACL token, only set if provided"
  type        = string
  default     = ""
}
variable "consul_acl_default_policy" {
  description = "Default ACL policy"
  type        = string
  default     = "deny"
}
variable "consul_acl_token_persistence" {
  description = "Define if tokens set using the API will be persisted to disk or not"
  type        = string
  default     = "True"
}
variable "consul_acl_datacenter" {
  description = "ACL authoritative datacenter name"
  type        = string
  default     = "tmi-w01-dc01" #Troy is default
}
variable "consul_acl_down_policy" {
  description = "Default ACL down policy"
  type        = string
  default     = "allow"
}
variable "consul_acl_agent_token" {
  description = "Used for clients and servers to perform internal operations to the service catalog"
  type        = string
  default     = ""
}
variable "consul_acl_agent_master_token" {
  description = "A special access token that has agent ACL policy write privileges on each agent where it is configured"
  type        = string
  default     = ""
}
variable "consul_acl_master_token" {
  description = "ACL master token"
  type        = string
  default     = ""
}
variable "consul_acl_master_token_display" {
  description = "Display generated ACL Master Token"
  type        = string
  default     = ""
}
##TODO: Determine how to handle this - required in non-Troy (primary) datacenters
variable "consul_acl_replication_token" {
  description = "ACL replication token"
  type        = string
  default     = ""
}
variable "consul_addresses_http" {
  description = ""
  type        = string
  default     = "127.0.0.1 {{ consul_bind_address }}"
}
variable "consul_ports" {
  description = ""
  type        = map(any)
  default     = { "grpc" = "8502", "dns" = "8600", "http" = "8500", "https" = "8501", "rpc" = "8400", "serf_lan" = "8301", "serf_wan" = "8302", "server" = "8300" }
}
variable "consul_dnsmasq_enable" {
  description = "Whether to install and configure DNS API forwarding on port 53 using DNSMasq"
  type        = string
  default     = "True"
}
variable "consul_dnsmasq_servers" {
  description = "Upstream DNS servers used by dnsmasq"
  type        = list(string)
  default     = []
}
variable "consul_dnsmasq_revservers" {
  description = "Reverse lookup subnets"
  type        = list(string)
  default     = []
}
variable "consul_iptables_enable" {
  description = "Whether to enable iptables rules for DNS forwarding to Consul"
  type        = string
  default     = "False"
}
##TODO: Determine if should be Infoblox
variable "consul_recursors" {
  description = "List of upstream DNS servers"
  type        = list(any)
  default     = ["10.254.203.31", "10.254.203.32", "10.254.203.33"]
}
## Autopilot Vars ##
##TODO: Add to main.tf after acquiring Enterprise
variable "consul_autopilot_enable" {
  description = "Enable Autopilot config"
  type        = string
  default     = "False"
}
variable "consul_autopilot_cleanup_dead_Servers" {
  description = "Dead servers will periodically be cleaned up and removed from the Raft peer set"
  type        = string
  default     = "False"
}
variable "consul_autopilot_last_contact_threshold" {
  description = "Sets the threshold for time since last contact"
  type        = string
  default     = "200ms"
}
variable "consul_autopilot_max_trailing_logs" {
  description = "Used in the serf health check to set a max-number of log entries nodes can trail the leader"
  type        = string
  default     = "250"
}
variable "consul_autopilot_server_stabilization_time" {
  description = "Time to allow a new node to stabilize"
  type        = string
  default     = "10s"
}
variable "consul_autopilot_redundancy_zone_tag" {
  description = "Override with CONSUL_AUTOPILOT_REDUNDANCY_ZONE_TAG environment variable"
  type        = string
  default     = "az"
}
variable "consul_autopilot_disable_upgrade_migration" {
  description = "Override with CONSUL_AUTOPILOT_DISABLE_UPGRADE_MIGRATION environment variable"
  type        = string
  default     = "False"
}
variable "consul_autopilot_upgrade_version_tag" {
  description = "Override with CONSUL_AUTOPILOT_UPGRADE_VERSION_TAG environment variable"
  type        = string
  default     = ""
}
variable "consul_debug" {
  description = "Enables the generation of additional config files in the Consul config directory for debug purpose"
  type        = string
  default     = "False"
}
variable "consul_config_custom" {
  type = any
  default = {
    "telemetry" = {
      "prometheus_retention_time" = "30s"
    }
  }
}

#### Docker Vars ####
variable "docker_daemon_options" {
  description = ""
  type        = any
  default = {
    "dns"          = ["10.254.203.31", "10.254.203.32", "10.254.203.33"]
    "metrics-addr" = "0.0.0.0:9323"
    "experimental" = true
  }
}

#### Nomad Vars ####
variable "nomad_debug" {
  description = "Nomad debug mode"
  type        = string
  default     = "no"
}
variable "nomad_skip_ensure_all_hosts" {
  description = "Allow running the role even if not all instances are connected"
  type        = string
  default     = "no"
}
variable "nomad_allow_purge_config" {
  description = "Allow purging obsolete configuration files. For example, remove server configuration if instance is no longer a server"
  type        = string
  default     = "no"
}
variable "nomad_version" {
  description = ""
  type        = string
  default     = "1.2.6"
}
variable "nomad_bin_dir" {
  description = "Nomad binary installation path"
  type        = string
  default     = "/usr/local/bin"
}
variable "nomad_config_dir" {
  description = "Nomad configuration file path"
  type        = string
  default     = "/etc/nomad.d"
}
variable "nomad_data_dir" {
  description = "Nomad data path"
  type        = string
  default     = "/opt/nomad"
}
variable "nomad_lockfile" {
  description = "Nomad lockfile path"
  type        = string
  default     = "/var/lock/subsys/nomad"
}
variable "nomad_run_dir" {
  description = "Nomad run path"
  type        = string
  default     = "/var/run/nomad"
}
variable "nomad_manage_user" {
  description = "Manage Nomad user"
  type        = string
  default     = "no"
}
variable "nomad_user" {
  description = "Nomad OS username"
  type        = string
  default     = "root"
}
variable "nomad_user_uid" {
  description = "Nomad user's uid"
  type        = string
  default     = "4646"
}
variable "nomad_manage_group" {
  description = "Manage Nomad group"
  type        = string
  default     = "no"
}
variable "nomad_group" {
  description = "Nomad OS group"
  type        = string
  default     = "bin"
}
variable "nomad_group_gid" {
  description = "Nomad group's gid"
  type        = string
  default     = "4646"
}
variable "nomad_region" {
  description = "Default region"
  type        = string
  default     = ""
}
variable "nomad_datacenter" {
  description = "Nomad datacenter label"
  type        = string
  default     = "tmi-w01-dc01"
}
variable "nomad_log_level" {
  description = "Logging level"
  type        = string
  default     = "INFO"
}
variable "nomad_syslog_enable" {
  description = "Log to syslog"
  type        = string
  default     = "True"
}
variable "nomad_node_role" {
  description = "Nomad node role - server, client or both"
  type        = string
  default     = "client"
}
variable "nomad_leave_on_terminate" {
  description = ""
  type        = string
  default     = "yes"
}
variable "nomad_leave_on_interrupt" {
  description = ""
  type        = string
  default     = "yes"
}
variable "nomad_disable_update_check" {
  description = "Disable update check"
  type        = string
  default     = "no"
}
variable "nomad_retry_max" {
  description = "Max retry join attempts"
  type        = number
  default     = 0
}
variable "nomad_retry_join" {
  description = "Enable retry join"
  type        = string
  default     = "no"
}
variable "nomad_retry_interval" {
  description = "Retry join interval"
  type        = string
  default     = "30s"
}
variable "nomad_rejoin_after_leave" {
  description = "Rejoin after leave"
  type        = string
  default     = "no"
}
variable "nomad_enabled_schedulers" {
  description = "List of enabled schedulers"
  type        = list(string)
  default     = ["service", "batch", "system"]
}
variable "nomad_node_gc_threshold" {
  description = "Node garbage collection threshold"
  type        = string
  default     = "24h"
}
variable "nomad_job_gc_threshold" {
  description = "Job garbage collection threshold"
  type        = string
  default     = "4h"
}
variable "nomad_eval_gc_threshold" {
  description = "Eval garbage collection threshold"
  type        = string
  default     = "1h"
}
variable "nomad_deployment_gc_threshold" {
  description = "Deployment garbage collection threshold"
  type        = string
  default     = "1h"
}
variable "nomad_encrypt_enable" {
  description = "Enable Gossip Encryption even if nomad_encrypt is not set"
  type        = string
  default     = "False"
}
##TODO: Source from Vault
variable "nomad_encrypt" {
  description = "Set the encryption key; should be the same across a cluster. If not present and nomad_encrypt_enable is true, the key will be generated & retrieved from the bootstrapped server."
  type        = string
  default     = ""
}
variable "nomad_raft_protocol" {
  description = "Specifies the version of raft protocal, which used by nomad servers for communication."
  type        = number
  default     = 2
}
variable "nomad_authoritative_region" {
  description = "Specifies the authoritative region, which provides a single source of truth for global configurations such as ACL Policies and global ACL tokens"
  type        = string
  default     = "tmi"
}
variable "nomad_node_class" {
  description = "Nomad node class"
  type        = string
  default     = "feature"
}
variable "nomad_no_host_uuid" {
  description = "Force the UUID generated by the client to be randomly generated"
  type        = string
  default     = "no"
}
variable "nomad_max_kill_timeout" {
  description = "Max kill timeout"
  type        = string
  default     = "30s"
}
variable "nomad_network_interface" {
  description = "Nomad scheduler will choose from the IPs of this interface for allocating tasks"
  type        = string
  default     = ""
}
variable "nomad_network_speed" {
  description = "Overide network link speed (0 = no overide)"
  type        = number
  default     = 0
}
variable "nomad_cpu_total_compute" {
  description = "Overide cpu compute (0 = no overide)"
  type        = number
  default     = 0
}
variable "nomad_gc_interval" {
  description = "Client garbage collection interval"
  type        = string
  default     = "1m"
}
variable "nomad_gc_disk_usage_threshold" {
  description = "Disk usage threshold percentage for garbage collection"
  type        = number
  default     = 80
}
variable "nomad_gc_inodes_usage_threshold" {
  description = "Inode usage threshold percentage for garbage collection"
  type        = number
  default     = 70
}
variable "nomad_gc_parallel_destroys" {
  description = "Inode usage threshold percentage for garbage collection"
  type        = number
  default     = 2
}
variable "nomad_reserved_cpu" {
  description = "Reserved client CPU"
  type        = number
  default     = 0
}
variable "nomad_reserved_memory" {
  description = "Reserved client memory"
  type        = number
  default     = 0
}
variable "nomad_reserved_disk" {
  description = "Reserved client memory"
  type        = number
  default     = 0
}
variable "nomad_reserved_ports" {
  description = "Reserved client ports"
  type        = number
  default     = 22
}
variable "nomad_host_volumes" {
  description = "Storage data disk parameter, example"
  type        = any
  default     = {}
}
variable "nomad_options" {
  description = ""
  type        = map(any)
  default = {
    "driver.raw_exec.enable" = "1"
    "driver.java.enable"     = "0"
    "docker.cleanup.image"   = "false"
    "docker.volumes.enabled" = "true"
  }
}
variable "nomad_meta" {
  description = "Meta data"
  type        = map(any)
  default = {
    "node-switcher" = "on"
    "purpose"       = "ops"
  }
}
variable "nomad_ports_http" {
  description = "Http port"
  type        = number
  default     = 4646
}
variable "nomad_ports_rpc" {
  description = "RPC port"
  type        = number
  default     = 4647
}
variable "nomad_ports_serf" {
  description = "Serf port"
  type        = number
  default     = 4648
}
variable "nomad_podman_enable" {
  description = "Installs the podman plugin"
  type        = string
  default     = "False"
}
variable "nomad_docker_enable" {
  description = "Install Docker subsystem on nodes"
  type        = string
  default     = "yes"
}
variable "nomad_plugins" {
  description = "Allow you configure nomad plugins"
  type        = any
  default     = {}
}
variable "nomad_use_consul" {
  description = "Bootstrap nomad via native consul zero-configuration support assumes consul default ports etc."
  type        = string
  default     = "True"
}
variable "nomad_consul_address" {
  description = "The address of your consul API, use it in combination with nomad_use_consul=True"
  type        = string
  default     = "127.0.0.1:8500"
}
variable "nomad_consul_servers_service_name" {
  description = "The name of the consul service for your nomad servers"
  type        = string
  default     = "nomad"
}
variable "nomad_consul_clients_service_name" {
  description = "The name of the consul service for your nomad clients"
  type        = string
  default     = "nomad-client"
}
variable "nomad_consul_token" {
  description = "Token to use for consul interaction"
  type        = string
  default     = ""
}
variable "nomad_acl_enabled" {
  description = "Enable ACLs"
  type        = string
  default     = "yes"
}
variable "nomad_acl_token_ttl" {
  description = "TTL for tokens"
  type        = string
  default     = "30s"
}
variable "nomad_acl_policy_ttl" {
  description = "TTL for policies"
  type        = string
  default     = "30s"
}
##TODO: Source from Vault
variable "nomad_env_namespace" {
  description = "nomad namespace used by Nomad Prod - Nonprod"
  type        = string
  default     = ""
}

variable "nomad_purpose" {
  description = "nomad node purpose"
  type        = string
  default     = "heater"
}
variable "nomad_acl_replication_token" {
  description = "Token to use for acl replication on non authoritive servers"
  type        = string
  default     = ""
}
variable "nomad_vault_enabled" {
  description = "Enable Vault"
  type        = string
  default     = "yes"
}
variable "nomad_vault_allow_unauthenticated" {
  description = "Allow users to use vault without providing their own token"
  type        = string
  default     = "yes"
}
variable "nomad_vault_address" {
  description = "Vault address to use"
  type        = string
  default     = "https://vault.service.consul:8200"
}
variable "nomad_vault_create_from_role" {
  description = "Role to create tokens from"
  type        = string
  default     = "nomad-cluster"
}
variable "nomad_vault_ca_file" {
  description = "Path of CA cert to use with vault"
  type        = string
  default     = ""
  #default     = "/opt/nomad/tls/consul-agent-ca.pem"
}
variable "nomad_vault_ca_path" {
  description = "Path of a folder containing CA cert(s) to use with vault"
  type        = string
  default     = ""
  #default     = "/opt/nomad/tls"
}
variable "nomad_vault_cert_file" {
  description = "Path to a certificate to use with Vault"
  type        = string
  default     = ""
  #default     = "/opt/nomad/tls/combined_ca.crt"
}
variable "nomad_vault_key_file" {
  description = "Path to a private key file to use with Vault"
  type        = string
  default     = ""
  #default     = "/opt/nomad/tls/vault.key"
}
variable "nomad_vault_tls_server_name" {
  description = "Optional string used to set SNI host when connecting to Vault"
  type        = string
  default     = ""
}
variable "nomad_vault_tls_skip_verify" {
  description = ""
  type        = string
  default     = "no"
}
variable "nomad_vault_namespace" {
  description = "Vault namespace used by Nomad"
  type        = string
  default     = ""
}
variable "nomad_tls_enable" {
  description = "Enable TLS"
  type        = string
  default     = "false"
}
##TODO: Add Nomad CA File
variable "nomad_ca_file" {
  description = "Use a ca for tls connection, nomad_cert_file and nomad_key_file are needed"
  type        = string
  default     = ""
}
##TODO: Add Nomad cert File
variable "nomad_cert_file" {
  description = "Use a certificate for tls connection, nomad_ca_file and nomad_key_file are needed"
  type        = string
  default     = ""
}
##TODO: Add Nomad key File
variable "nomad_key_file" {
  description = "Use a key for tls connection, nomad_cert_file and nomad_key_file are needed"
  type        = string
  default     = ""
}
variable "nomad_rpc_upgrade_mode" {
  description = "Use a certificate for tls connection, nomad_ca_file and nomad_key_file are needed, used only when the cluster is being upgraded to TLS, and removed after the migration is complete. This allows the agent to accept both TLS and plaintext traffic."
  type        = string
  default     = "false"
}
variable "nomad_verify_server_hostname" {
  description = "Use a key for tls connection, nomad_cert_file and nomad_key_file are needed. Specifies if outgoing TLS connections should verify the server's hostname."
  type        = string
  default     = "false"
}
variable "nomad_verify_https_client" {
  description = "Use a key for tls connection, nomad_cert_file and nomad_key_file are needed. Specifies agents should require client certificates for all incoming HTTPS requests. The client certificates must be signed by the same CA as Nomad."
  type        = string
  default     = "false"
}
variable "nomad_group_name" {
  description = "Ansible group that contains all cluster nodes"
  type        = string
  default     = "all"
}
variable "nomad_telemetry" {
  description = ""
  type        = string
  default     = "true"
}
variable "nomad_telemetry_prometheus_metrics" {
  description = ""
  type        = string
  default     = "true"
}
variable "nomad_telemetry_publish_allocation_metrics" {
  description = "Specifies if Nomad should publish runtime metrics of allocations"
  type        = string
  default     = "true"
}
variable "nomad_telemetry_publish_node_metrics" {
  description = "Specifies if Nomad should publish runtime metrics of nodes."
  type        = string
  default     = "true"
}
variable "nomad_autopilot" {
  description = "Enable Nomad Autopilot"
  type        = string
  default     = "False"
}
variable "nomad_autopilot_cleanup_dead_servers" {
  description = "Specifies automatic removal of dead server nodes periodically and whenever a new server is added to the cluster"
  type        = string
  default     = "False"
}
variable "nomad_autopilot_last_contact_threshold" {
  description = "Specifies the maximum amount of time a server can go without contact from the leader before being considered unhealthy"
  type        = string
  default     = "250ms"
}
variable "nomad_autopilot_max_trailing_logs" {
  description = "Specifies the maximum number of log entries that a server can trail the leader by before being considered unhealthy"
  type        = number
  default     = 250
}
variable "nomad_autopilot_server_stabilization_time" {
  description = "Specifies the minimum amount of time a server must be stable in the 'healthy' state before being added to the cluster. Only takes effect if all servers are running Raft protocol version 3 or higher"
  type        = string
  default     = "10s"
}

#### Vault Server role vars ####
variable "vault_listener_localhost_enable" {
  description = "Set this to true if you enable listen vault on localhost"
  type        = string
  default     = "false"
}
variable "vault_privileged_install" {
  description = "Set this to true if you see permission errors when the vault files are downloaded and unpacked locally. This issue can show up if the role has been downloaded by one user (like root), and the installation is done with a different user"
  type        = string
  default     = "false"
}
variable "vault_version" {
  description = "Version to install"
  type        = string
  default     = "1.9.4"
}
variable "vault_enterprise" {
  description = "Set this to true when installing Vault Enterprise; this is not currently possible as a 'remote only' install method"
  type        = string
  default     = "false"
}
variable "vault_pkg" {
  description = "Package filename"
  type        = string
  default     = "vault_{{ vault_version }}_linux_amd64.zip"
}
variable "vault_enterprise_pkg" {
  description = "Package filename"
  type        = string
  default     = "vault-enterprise_{{ vault_version }}_{{ vault_os }}_{{ vault_architecture }}.zip"
}
variable "vault_zip_url" {
  description = "Package download URL"
  type        = string
  default     = "https://releases.hashicorp.com/vault/{{ vault_version }}/vault_{{ vault_version }}_linux_amd64.zip"
}
variable "vault_checksum_file_url" {
  description = "SHA summaries URL"
  type        = string
  default     = "https://releases.hashicorp.com/vault/{{ vault_version }}/vault_{{ vault_version}}_SHA256SUMS"
}
variable "vault_install_hashi_repo" {
  description = "Set this to true when installing Vault via HashiCorp Linux repository. When set, you can also define vault_hashicorp_key_url and vault_hashicorp_apt_repository_url to override the default URL of the GPG key loaded in apt keyring and the default URL of the apt repository used."
  type        = string
  default     = "false"
}
variable "vault_install_remotely" {
  description = "Set this to true will download Vault binary from each target instead of localhost"
  type        = string
  default     = "false"
}
variable "vault_shasums" {
  description = "SHA summaries filename (included for convenience not for modification)"
  type        = string
  default     = "vault_{{ vault_version }}_SHA256SUMS"
}
variable "vault_enterprise_shasums" {
  description = "SHA summaries filename (included for convenience not for modification)"
  type        = string
  default     = "vault-enterprise_{{ vault_version }}_SHA256SUMS"
}
variable "vault_bin_path" {
  description = "Binary installation path"
  type        = string
  default     = "/usr/local/bin"
}
variable "vault_config_path" {
  description = "Configuration file path"
  type        = string
  default     = "/etc/vault.d"
}
variable "vault_use_config_path" {
  description = "Use '{{ vault_config_path }}' to configure vault instead of {{ vault_main_config }}"
  type        = string
  default     = "false"
}
variable "vault_plugin_path" {
  description = "Path from where plugins can be loaded"
  type        = string
  default     = "/usr/local/lib/vault/plugins"
}
variable "vault_data_path" {
  description = "Data path"
  type        = string
  default     = "/var/vault"
}
variable "vault_log_path" {
  description = "Log path"
  type        = string
  default     = "/var/log/vault"
}
variable "vault_run_path" {
  description = "PID file location"
  type        = string
  default     = "/var/run/vault"
}
variable "vault_harden_file_perms" {
  description = "Whether this role should disallow Vault from writing into config and plugin path. This should be enabled to follow Production Hardening."
  type        = string
  default     = "false"
}
variable "vault_manage_user" {
  description = "Should this role manage the vault user?"
  type        = string
  default     = "true"
}
variable "vault_user" {
  description = "OS user name"
  type        = string
  default     = "vault"
}
variable "vault_group" {
  description = "OS group name"
  type        = string
  default     = "vault"
}
variable "vault_groups" {
  description = "OS additional groups as in ansibles user module"
  type        = string
  default     = ""
}
variable "vault_manage_group" {
  description = "Should this role manage the vault group?"
  type        = string
  default     = "true"
}
variable "vault_group_name" {
  description = "Inventory group name"
  type        = string
  default     = "vault_instances"
}
variable "vault_cluster_name" {
  description = "Cluster name label"
  type        = string
  default     = "dc1"
}
variable "vault_datacenter" {
  description = "Datacenter label"
  type        = string
  default     = "dc1"
}
variable "vault_ui" {
  description = "Enable vault web UI"
  type        = string
  default     = "true"
}
variable "vault_service_restart" {
  description = "Should the playbook restart Vault service when needed"
  type        = string
  default     = "true"
}
variable "vault_service_reload" {
  description = "Should the playbook reload Vault service when the main config changes"
  type        = string
  default     = "false"
}
variable "vault_start_pause_seconds" {
  description = "Some installations may need some time between the first Vault start and the first restart. Setting this to a value >0 will add a pause time after the first Vault start"
  type        = string
  default     = "0"
}
variable "vault_backend" {
  description = "Which storage backend should be selected, choices are: raft, consul, etcd, file, s3, and dynamodb"
  type        = string
  default     = "raft"
}
variable "vault_backend_tls_src_files" {
  description = "User-specified source directory for TLS files for storage communication"
  type        = string
  default     = "{{ vault_tls_src_files }}"
}
variable "vault_backend_tls_config_path" {
  description = "Path to directory containing backend tls config files"
  type        = string
  default     = "{{ vault_tls_config_path }}"
}
variable "vault_backend_tls_cert_file" {
  description = "Specifies the path to the certificate for backend communication (if supported)"
  type        = string
  default     = "{{ vault_tls_cert_file }}"
}
variable "vault_backend_tls_key_file" {
  description = "Specifies the path to the private key for backend communication (if supported)"
  type        = string
  default     = "{{ vault_tls_key_file }}"
}
variable "vault_backend_tls_ca_file" {
  description = "CA certificate used for backend communication (if supported). This defaults to system bundle if not specified"
  type        = string
  default     = "{{ vault_tls_ca_file }}"
}
variable "vault_raft_leader_tls_servername" {
  description = "TLS servername to use when connecting with HTTPS"
  type        = string
  default     = ""
}
variable "vault_raft_group_name" {
  description = "Inventory group name of servers hosting the raft backend"
  type        = string
  default     = "vault_raft_servers"
}
variable "vault_raft_data_path" {
  description = "Data path for Raft"
  type        = string
  default     = "{{ vault_data_path }}"
}
variable "vault_raft_node_id" {
  description = "Node_id for Raft"
  type        = string
  default     = "{{ inventory_hostname_short }}"
}
variable "vault_raft_performance_multiplier" {
  description = "Performance multiplier for Raft"
  type        = string
  default     = ""
}
variable "vault_raft_trailing_logs" {
  description = "Logs entries count left on log store after snapshot"
  type        = string
  default     = ""
}
variable "vault_raft_snapshot_threshold" {
  description = "Minimum Raft commit entries between snapshots"
  type        = string
  default     = ""
}
variable "vault_raft_max_entry_size" {
  description = "Maximum number of bytes for a Raft entry"
  type        = string
  default     = ""
}
variable "vault_raft_autopilot_reconcile_interval" {
  description = "Interval after which autopilot will pick up any state changes"
  type        = string
  default     = ""
}
variable "vault_raft_cloud_auto_join" {
  description = "Defines any cloud auto-join metadata. If supplied, Vault will attempt to automatically discover peers in addition to what can be provided via leader_api_addr"
  type        = string
  default     = "none"
}
variable "vault_raft_cloud_auto_join_exclusive" {
  description = "If set to true, any leader_api_addr occurences will be removed from the configuration. Keeping this to false will allow auto_join and leader_api_addr to coexist"
  type        = string
  default     = "false"
}
variable "vault_raft_cloud_auto_join_scheme" {
  description = "URI scheme to be used for auto_join"
  type        = string
  default     = "https"
}
variable "vault_raft_cloud_auto_join_port" {
  description = "Port to be used for auto_join"
  type        = number
  default     = 8200
}
variable "vault_service_registration_consul_enable" {
  description = "Enable Consul service registration"
  type        = string
  default     = "true"
}
variable "vault_service_registration_consul_template" {
  description = "Consul service registration template filename"
  type        = string
  default     = "service_registration_consul.hcl.j2"
}
variable "vault_service_registration_consul_address" {
  description = "host:port value for connecting to Consul service registration"
  type        = string
  default     = "consul.service.consul:8500"
}
variable "vault_service_registration_check_timeout" {
  description = "Specifies the check interval used to send health check information back to Consul."
  type        = string
  default     = "5s"
}
variable "vault_service_registration_disable_registration" {
  description = "Specifies whether Vault should register itself with Consul"
  type        = string
  default     = "false"
}
variable "vault_service_registration_consul_scheme" {
  description = "Scheme for Consul service registration"
  type        = string
  default     = "http"
}
variable "vault_service_registration_consul_service" {
  description = "Name of the Vault service to register in Consul"
  type        = string
  default     = "vault"
}
variable "vault_service_registration_consul_service_tags" {
  description = "Specifies a comma-separated list of tags to attach to the service registration in Consul."
  type        = string
  default     = ""
}
variable "vault_service_registration_consul_service_address" {
  description = "Specifies a service-specific address to set on the service registration in Consul"
  type        = string
  default     = ""
}
variable "vault_service_registration_consul_token" {
  description = "ACL token for registering with Consul service registration"
  type        = string
  default     = ""
  sensitive   = true
}
variable "vault_service_registration_consul_tls_config_path" {
  description = "Path to TLS certificate and key"
  type        = string
  default     = "{{ vault_tls_config_path }}"
}
variable "vault_service_registration_consul_tls_ca_file" {
  description = "CA certificate filename"
  type        = string
  default     = "{{ vault_tls_ca_file }}"
}
variable "vault_service_registration_consul_tls_cert_file" {
  description = "Server certificate"
  type        = string
  default     = "{{ vault_tls_cert_file }}"
}
variable "vault_service_registration_consul_tls_key_file" {
  description = "Server key"
  type        = string
  default     = "{{ vault_tls_key_file }}"
}
variable "vault_service_registration_consul_tls_min_version" {
  description = "Minimum acceptable TLS version"
  type        = string
  default     = "{{ vault_tls_min_version }}"
}
variable "vault_service_registration_consul_tls_skip_verify" {
  description = "Disable verification of TLS certificates. Using this option is highly discouraged"
  type        = string
  default     = "false"
}
variable "vault_log_level" {
  description = "Log level - trace, debug, info, warn or err"
  type        = string
  default     = "info"
}
variable "vault_iface" {
  description = "Network interface"
  type        = string
  default     = "eth1"
}
variable "vault_address" {
  description = "Primary network interface address to use"
  type        = string
  default     = "{{ vault_protocol }}://{{ ansible_default_ipv4.address }}:{{ vault_port }}"
}
variable "vault_port" {
  description = "TCP port number to on which to listen"
  type        = string
  default     = "8200"
}
variable "vault_max_lease_ttl" {
  description = "Configures the maximum possible lease duration for tokens and secrets"
  type        = string
  default     = "768h" //32 days
}
variable "vault_default_lease_ttl" {
  description = "Configures the default lease duration for tokens and secrets"
  type        = string
  default     = "768h" //32 days
}
variable "vault_main_config" {
  description = "Main configuration file name (full path)"
  type        = string
  default     = "{{ vault_config_path }}/vault_main.hcl"
}
variable "vault_main_configuration_template" {
  description = "Vault main configuration template file"
  type        = string
  default     = "vault_main_configuration.hcl.j2"
}
variable "vault_http_proxy" {
  description = "Address to be used as the proxy for HTTP and HTTPS requests unless overridden by vault_https_proxy or vault_no_proxy"
  type        = string
  default     = ""
}
variable "vault_https_proxy" {
  description = "Address to be used as the proxy for HTTPS requests unless overridden by vault_no_proxy"
  type        = string
  default     = ""
}
variable "vault_no_proxy" {
  description = "Comma separated values which specify hosts that should be exluded from proxying. Follows golang conventions"
  type        = string
  default     = ""
}
variable "vault_cluster_address" {
  description = "Address to bind to for cluster server-to-server requests"
  type        = string
  default     = "{{ ansible_default_ipv4.address }}:{{ (vault_port | int) + 1}}"
}
variable "vault_cluster_addr" {
  description = "Address to advertise to other Vault servers in the cluster for request forwarding"
  type        = string
  default     = "{{ vault_protocol }}://{{ vault_cluster_address }}"
}
variable "vault_api_addr" {
  description = "HA Client Redirect address"
  type        = string
  default     = "{{ vault_protocol }}://{{ ansible_default_ipv4.address }}:{{ vault_port }}"
}
variable "vault_disable_api_health_check" {
  description = "Flag for disabling the health check on vaults api address"
  type        = string
  default     = "false"
}
variable "vault_cluster_disable" {
  description = "Disable HA clustering"
  type        = string
  default     = "false"
}
variable "validate_certs_during_api_reachable_check" {
  description = "Disable Certificate Validation for API reachability check"
  type        = string
  default     = "true"
}
variable "vault_proxy_protocol_behavior" {
  description = "May be one of use_always, allow_authorized, or deny_unauthorized"
  type        = string
  default     = ""
}
variable "vault_tls_config_path" {
  description = "Path to TLS certificate and key"
  type        = string
  default     = "/etc/vault/tls"
}
variable "vault_tls_disable" {
  description = "Disable TLS"
  type        = string
  default     = "1"
}
//TODO: Needed for Raft?
variable "vault_tls_gossip" {
  description = "Enable TLS Gossip to storage (if supported)"
  type        = string
  default     = "0"
}
variable "vault_tls_src_files" {
  description = "User-specified source directory for TLS files"
  type        = string
  default     = "{{ role_path }}/files"
}
variable "vault_tls_ca_file" {
  description = "CA certificate filename"
  type        = string
  default     = "ca.crt"
}
variable "vault_tls_cert_file" {
  description = "Server certificate"
  type        = string
  default     = "server.crt"
}
variable "vault_tls_key_file" {
  description = "Server key"
  type        = string
  default     = "server.key"
}
variable "vault_tls_min_version" {
  description = "Minimum acceptable TLS version"
  type        = string
  default     = "tls12"
}
variable "vault_tls_cipher_suites" {
  description = "Comma-separated list of supported ciphersuites"
  type        = string
  default     = ""
}
variable "vault_tls_prefer_server_cipher_suites" {
  description = "Prefer server's cipher suite over client cipher suite"
  type        = string
  default     = "false"
}
variable "vault_tls_require_and_verify_client_cert" {
  description = "Require clients to present a valid client certificate"
  type        = string
  default     = "false"
}
variable "vault_tls_disable_client_certs" {
  description = "Disable requesting for client certificates"
  type        = string
  default     = "false"
}
variable "vault_tls_copy_keys" {
  description = "Copy TLS files from src to dest"
  type        = string
  default     = "true"
}
variable "vault_tls_files_remote_src" {
  description = "Copy from remote source if TLS files are already on host"
  type        = string
  default     = "false"
}
variable "vault_x_forwarded_for_authorized_addrs" {
  description = "Comma-separated list of source IP CIDRs for which an X-Forwarded-For header will be trusted"
  type        = string
  default     = ""
}
variable "vault_bsdinit_template" {
  description = "BSD init template file"
  type        = string
  default     = ""
}
variable "vault_sysvinit_template" {
  description = "SysV init template file"
  type        = string
  default     = ""
}
variable "vault_debian_init_template" {
  description = "Debian init template file"
  type        = string
  default     = ""
}
variable "vault_systemd_template" {
  description = "Systemd service template file"
  type        = string
  default     = "vault_service_systemd.j2"
}
variable "vault_systemd_service_name" {
  description = "Systemd service unit name"
  type        = string
  default     = "vault"
}
//TODO: Where to supply vault_prometheus_retention_time?
variable "vault_telemetry_enabled" {
  description = "Enable Vault telemetry"
  type        = string
  default     = "true"
}
variable "vault_unauthenticated_metrics_access" {
  description = ""
  type        = string
  default     = "false"
}

#### Vault Agent role vars ####
variable "vault_agent_role_id" {
  description = "Role ID for approle with which to authenticate Vault Agent to the Vault cluster"
  sensitive   = true
  type        = string
  default     = ""
}
variable "vault_agent_secret_id" {
  description = "Secret ID for approle with which to authenticate Vault Agent to the Vault cluster"
  sensitive   = true
  type        = string
  default     = ""
}
variable "vault_agent_version" {
  description = "Version of Vault to use for Vault Agent install"
  type        = string
  default     = "1.9.4"
}
variable "vault_api_address" {
  description = "HTTP API address of Vault cluster for Vault Agent to use"
  type        = string
  default     = "https://vault.service.tmi-w01-dc01.consul:8200"
}
variable "vault_agent_log_level" {
  description = "Logging level of Vault Agent service: `trace`, `debug`, `info`, `warn`, or `err`"
  type        = string
  default     = "warn"
}
variable "vault_agent_templates" {
  description = ""
  type        = any
  default     = []
}
variable "vault_skip_verify" {
  description = ""
  type        = string
  default     = "False"
}
variable "vault_ca_cert" {
  description = "Path on the local disk to a single PEM-encoded CA certificate to verify the Vault server's SSL certificate"
  type        = string
  default     = "/opt/vault/tls/consul-agent-ca.pem"
}
variable "vault_ca_path" {
  description = "Path on the local disk to a directory of PEM-encoded CA certificates to verify the Vault server's SSL certificate"
  type        = string
  default     = "/opt/vault/tls"
}
variable "vault_client_cert" {
  description = "Path on the local disk to a single PEM-encoded CA certificate to use for TLS authentication to the Vault server"
  type        = string
  default     = "/opt/vault/tls/combined_ca.crt"
}
variable "vault_client_key" {
  description = "Path on the local disk to a single PEM-encoded private key matching the client certificate from client_cert"
  type        = string
  default     = "/opt/vault/tls/vault-key.pem"
}
variable "vault_ca_cert_src" {
  description = "Path on the local disk to a single PEM-encoded CA certificate to verify the Vault server's SSL certificate to copy to target"
  type        = string
  default     = "/opt/devops-local/ssl/certs/consul-agent-ca.pem"
}
variable "vault_client_cert_src" {
  description = "Path on the local disk to a single PEM-encoded CA certificate to use for TLS authentication to the Vault server to copy to target"
  type        = string
  default     = "/opt/devops-local/ssl/certs/combined_ca.crt"
}
variable "vault_client_key_src" {
  description = "Path on the local disk to a single PEM-encoded private key matching the client certificate from client_cert to copy to target"
  type        = string
  default     = "/opt/devops-local/ssl/keys/vault-key.pem"
}
variable "vault_agent_num_retries" {
  description = "Specify how many times a failing request will be retried. A value of 0 translates to the default, i.e. 12 retries. A value of -1 disables retries."
  type        = number
  default     = -1
}
variable "vault_agent_exit_on_retry_failure" {
  description = ""
  type        = string
  default     = "true"
}
##TODO: Derive from cluster prefix
variable "vault_consul_role_cluster_type" {
  description = ""
  type        = string
  default     = "true"
}

########## SECRETS ##########
variable "tmi_devtest_minio_s3_streaming_access_key" {
  description = "Troy Non-Prod S3 Streaming Access Key"
  type        = string
  default     = ""
}

variable "tmi_devtest_minio_s3_streaming_secret_key" {
  description = "Troy Non-Prod S3 Streaming Secret Key"
  type        = string
  default     = ""
}

variable "tmi_prod_minio_s3_streaming_access_key" {
  description = "Troy Prod S3 Streaming Access Key"
  type        = string
  default     = ""
}

variable "tmi_prod_minio_s3_streaming_secret_key" {
  description = "Troy Prod S3 Streaming Secret Key"
  type        = string
  default     = ""
}

variable "dal_devtest_minio_s3_streaming_access_key" {
  description = "Dallas Non-Prod S3 Streaming Access Key"
  type        = string
  default     = ""
}

variable "dal_devtest_minio_s3_streaming_secret_key" {
  description = "Dallas Non-Prod S3 Streaming Secret Key"
  type        = string
  default     = ""
}

variable "dal_prod_minio_s3_streaming_access_key" {
  description = "Dallas Prod S3 Streaming Access Key"
  type        = string
  default     = ""
}

variable "dal_prod_minio_s3_streaming_secret_key" {
  description = "Dallas Prod S3 Streaming Secret Key"
  type        = string
  default     = ""
}
variable "minio_s3_web_access_key" {
  description = "S3 Web Access Key"
  type        = string
  default     = ""
}

variable "minio_s3_web_secret_key" {
  description = "S3 Web Secret Key"
  type        = string
  default     = ""
}
variable "minio_s3_minio_access_key" {
  description = "S3 Minio Testing Access Key"
  type        = string
  default     = ""
}
variable "minio_s3_minio_secret_key" {
  description = "S3 Minio Testing Secret Key"
  type        = string
  default     = ""
}
variable "minio_s3_data_access_key" {
  description = "S3 Minio Testing Access Key"
  type        = string
  default     = ""
}
variable "minio_s3_data_secret_key" {
  description = "S3 Minio Testing Secret Key"
  type        = string
  default     = ""
}

variable "known_hosts_targets" {
  description = "Known Hosts Targets"
  type        = list(string)
  default     = []
}
variable "known_hosts_user" {
  description = "Known Hosts User"
  type        = string
  default     = ""
}

variable "docker_vault_login" {
  description = "Docker Vault Login Config"
  type        = any
  default     = {}
}

variable "vault_docker_secrets" {
  description = "Vault Docker Secrets"
  type        = any
  default     = {}
}

#nfs server
variable "nfs_mount_server" {
  description = "NFS server ipaddress"
  type        = any
  default     = {}
}

#nfs mount options
variable "nfs_mount_options" {
  description = "NFS Mount Options for fstab"
  type        = any
  default     = {}
}

#nfs mount path
variable "nfs_mount_path" {
  description = "path on new host for mount to map"
  type        = any
  default     = {}
}

########## PROVIDERS ##########
// TODO: Optional providers...?
//       Might be able to use --> terraform init -from-module="..."
// variable "use_vault_provider" {
//   description = "Use vault provider or not"
//   default = false
// }
