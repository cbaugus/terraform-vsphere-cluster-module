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
##TODO: Determine default provisioned disks
variable "provisioned_disks" {
  description = "Storage data disk parameter, example"
  type        = any
  default     = {}
}
variable "growr_provisioned_disks" {
  description = "Storage data disk parameter, holding paramaters for provisioning with growr ansible role"
  type        = any
  default     = {}
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
  default     = "/opt/devops-local/ssl/keys/key.pem"
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
  default     = "/opt/devops-local/ssl/keys/key.pem"
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
