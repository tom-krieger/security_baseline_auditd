require 'spec_helper'

describe 'security_baseline_auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline_auditd' => {
            'access' => false,
            'action_mail_acct' => 'root',
            'actions' => true,
            'admin_space_left_action' => 'halt',
            'auditing_process' => 'linux16 /boot/vmlinuz-3.10.0-1062.1.1.el7.x86_64 root=UUID=f41e390f-835b-4223-a9bb-9b45984ddf8d ro console=tty0 console=ttyS0,115200n8 crashkernel=auto console=ttyS0,115200 LANG=en_US.UTF-8\n\tlinux16 /boot/vmlinuz-3.10.0-957.1.3.el7.x86_64 root=UUID=f41e390f-835b-4223-a9bb-9b45984ddf8d ro console=tty0 console=ttyS0,115200n8 crashkernel=auto console=ttyS0,115200 LANG=en_US.UTF-8\n\tlinux16 /boot/vmlinuz-0-rescue-05cb8c7b39fe0f70e3ce97e5beab809d root=UUID=f41e390f-835b-4223-a9bb-9b45984ddf8d ro console=tty0 console=ttyS0,115200n8 crashkernel=auto console=ttyS0,115200',
            'delete' => false,
            'identity' => false,
            'immutable' => true,
            'logins' => false,
            'mac-policy' => false,
            'max_log_file' => '32\n keep_logs',
            'max_log_file_action' => 'keep_logs',
            'modules' => false,
            'mounts' => false,
            'perm-mod' => false,
            'priv-cmds' => false,
            'priv-cmds-rules' => {
              '/' => [ '-a always,exit -S all -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/mount.nfs -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/libexec/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', 
                       '-a always,exit -S all -F path=/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged' ]
            },
            'scope' => false,
            'session' => false,
            'session-logins' => false,
            'space_left_action' => 'email',
            'srv_auditd' => 'enabled',
            'system-locale' => false,
            'time-change' => false
          }
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'automounting',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
