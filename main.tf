locals {
  ansible_extra_vars = {
    "ansible_python_interpreter"             = var.ansible_python_interpreter


    "growr_env" = merge([for index, disk in var.growr_provisioned_disks : merge({
      // Regular Vars
      "LABEL_${disk.DEVICE_DRIVE}" = disk["LABEL"],
    })]...)

    "known_hosts_user"    = var.known_hosts_user
    "known_hosts_targets" = var.known_hosts_targets
  }
}

module "virtual_machines" {
  source  = "app.terraform.io/baugus-lab/vm-module/vsphere"
  version = "v1.0.4"
  count   = tonumber(var.num_instances)
  network = {
    (data.vsphere_network.network.name) = var.ip_address
  }
  network_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  ### Disks section
  disk_label     = ["${var.name_prefix}-disk0"]          ### disk0
  disk_size_gb   = [var.disk_size[var.disk_size_type]]   ### disk0
  disk_datastore = data.vsphere_datastore.datastore.name ### disk0
  scsi_type      = "lsilogic"
  data_disk = { for index, disk in var.provisioned_disks : disk.label => {
    "size_gb"                   = "${var.disk_size[disk.disk_size]}"
    "thin_provisioned"          = "${disk.thin_provisioned}"
    "eagerly_scrub"             = "${disk.eagerly_scrub}"
    "datastore_id"              = "${data.vsphere_datastore.datastore.id}"
    "data_disk_scsi_controller" = "${disk.data_disk_scsi_controller}"
    }
  }
  vmname                      = "${var.name_prefix}-${count.index}"
  vmtemp                      = data.vsphere_virtual_machine.template.name
  tag_ids                     = var.vsphere_tag_ids
  instances                   = var.num_instances
  cpu_number                  = var.num_cores[var.cores_count_type]
  ram_size                    = var.mem_size[var.mem_size_type]
  dc                          = var.vsphere_datacenter
  vmrp                        = data.vsphere_resource_pool.resource_pool.name
  vmfolder                    = var.vsphere_folder
  vmdomain                    = "local.domain"
  wait_for_guest_net_timeout  = 30
  wait_for_guest_net_routable = false

  ##Provisioning configurations
  remote_exec_command      = var.remote_exec_command
  remote_exec_user         = var.remote_exec_user
  remote_exec_ssh_key_file = var.remote_exec_ssh_key_file
  remote_exec_timeout      = var.remote_exec_timeout
  local_exec_user          = var.local_exec_user
  local_exec_ssh_key_file  = var.local_exec_ssh_key_file
  path_to_ansible          = var.path_to_ansible
  ansible_args             = format("--extra-vars '%#v' -e 'hostname=${var.name_prefix}-${count.index}' -e 'nomad_node_name=${var.name_prefix}-${count.index}' -vvv -b", local.ansible_extra_vars)
}
