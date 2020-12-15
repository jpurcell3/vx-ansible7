---
- hosts: "{{ vxm }}"
#  vars_files:
#    - /etc/ansible/host_vars/{{ vxm }}

  collections:
  - dellemc.vxrail
  tasks:
  - include_role:
      name: vx-copyconfig

- hosts: localhost
  vars_files:
    - /etc/ansible/host_vars/{{ vxm }}
  collections:
  - vmware
  tasks:
  - name: Maint Mode test
    vmware_maintenancemode:
      hostname: "{{ vcenter }}"
      username: "{{ vcadmin }}"
      password: "{{ vcpasswd }}"
      esxi_hostname: "{{ esxhost }}"
      vsan: ensureObjectAccessibility
      evacuate: yes
      timeout: 3600
      validate_certs: false
      state: present
    delegate_to: localhost

  - name: Disabled Maintenance Mode on host
    vmware_maintenancemode:
      hostname: "{{ vcenter }}"
      username: "{{ vcadmin }}"
      password: "{{ vcpasswd }}"
      esxi_hostname: "{{ esxhost }}"
      vsan: ensureObjectAccessibility
      evacuate: yes
      timeout: 3600
      validate_certs: false
      state: absent 
    delegate_to: localhost

- hosts: localhost
  collections:
  - dellemc.vxrail
  tasks:
  - include_role:
      name: vx-intlcm
    tags: upgrade
