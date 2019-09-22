# frozen_string_literal: true

require 'facter/helpers/check_values'
require 'pp'

# security_baseline_auditd.rb
# Gather facts around auditd

Facter.add('security_baseline_auditd') do
  confine osfamily: 'RedHat'
  setcode do
    security_baseline_auditd = {}
    arch = Facter.value(:architecture)
    val = Facter::Core::Execution.exec('grep max_log_file /etc/audit/auditd.conf')
    security_baseline_auditd['max_log_file'] = if val.empty? || val.nil?
                                                 'none'
                                               else
                                                 val
                                               end

    val = Facter::Core::Execution.exec('grep space_left_action /etc/audit/auditd.conf')
    security_baseline_auditd['space_left_action'] = if val.empty? || val.nil?
                                                      'none'
                                                    else
                                                      val
                                                    end

    val = Facter::Core::Execution.exec('grep action_mail_acct /etc/audit/auditd.conf')
    security_baseline_auditd['action_mail_acct'] = if val.empty? || val.nil?
                                                     'none'
                                                   else
                                                     val
                                                   end

    val = Facter::Core::Execution.exec('grep admin_space_left_action /etc/audit/auditd.conf')
    security_baseline_auditd['admin_space_left_action'] = if val.empty? || val.nil?
                                                            'none'
                                                          else
                                                            val
                                                          end

    val = Facter::Core::Execution.exec('grep max_log_file_action /etc/audit/auditd.conf')
    security_baseline_auditd['max_log_file_action'] = if val.empty? || val.nil?
                                                        'none'
                                                      else
                                                        val
                                                      end

    security_baseline_auditd['srv_auditd'] = check_service_is_enabled('auditd')
    val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub2/grub.cfg')
    security_baseline_auditd['auditing_process'] = if val.empty? || val.nil?
                                                     'none'
                                                   else
                                                     val
                                                   end

    val = Facter::Core::Execution.exec('auditctl -l | grep time-change')
    expected = [
      '-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change',
      '-a always,exit -F arch=b32 -S clock_settime -F key=time-change',
      '-w /etc/localtime -p wa -k time-change',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change')
      expected.push('-a always,exit -F arch=b64 -S clock_settime -F key=time-change')
    end
    security_baseline_auditd['time-change'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep identity')
    expected = [
      '-w /etc/group -p wa -k identity',
      '-w /etc/passwd -p wa -k identity',
      '-w /etc/gshadow -p wa -k identity',
      '-w /etc/shadow -p wa -k identity',
      '-w /etc/security/opasswd -p wa -k identity',
    ]
    security_baseline_auditd['identity'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep system-locale')
    expected = [
      '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
      '-w /etc/issue -p wa -k system-locale',
      '-w /etc/issue.net -p wa -k system-locale',
      '-w /etc/hosts -p wa -k system-locale',
      '-w /etc/sysconfig/network -p wa -k system-locale',
      '-w /etc/sysconfig/network-scripts -p wa -k system-locale',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale')
    end
    security_baseline_auditd['system-locale'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep MAC-policy')
    expected = [
      '-w /etc/selinux -p wa -k MAC-policy',
      '-w /usr/share/selinux -p wa -k MAC-policy',
    ]
    security_baseline_auditd['mac-policy'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep logins')
    expected = [
      '-w /var/log/lastlog -p wa -k logins',
      '-w /var/run/faillock -p wa -k logins',
    ]
    security_baseline_auditd['logins'] = check_values(val, expected, true)

    val = Facter::Core::Execution.exec('auditctl -l | grep session')
    expected = [
      '-w /var/run/utmp -p wa -k session',
    ]
    security_baseline_auditd['session'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep "logins$"')
    expected = [
      '-w /var/log/wtmp -p wa -k logins',
      '-w /var/log/btmp -p wa -k logins',
    ]
    security_baseline_auditd['session-logins'] = check_values(val, expected, true)

    val = Facter::Core::Execution.exec('auditctl -l | grep perm_mod')
    expected = [
      '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
      '-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
      '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod')
      expected.push('-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod')
      expected.push('-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod')
    end
    security_baseline_auditd['perm-mod'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep access')
    expected = [
      '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access',
      '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access')
      expected.push('-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access')
    end
    security_baseline_auditd['access'] = check_values(val, expected)

    rules = {}
    expected = []
    Facter.value(:partitions).each do |_part, data|
      mount = data['mount']
      rules_raw = Facter::Core::Execution.exec('find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk \'{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged" }\'').split("\n")
      rules[mount] = rules_raw
      expected.push(rules_raw)
    end
    security_baseline_auditd['priv-cmds-rules'] = rules

    val = Facter::Core::Execution.exec('auditctl -l | grep "privileged$"')
    security_baseline_auditd['priv-cmds'] = check_values(val, expected, true, true)

    val = Facter::Core::Execution.exec('auditctl -l | grep "mounts$"')
    expected = [
      '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts')
    end
    security_baseline_auditd['mounts'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep "delete$"')
    expected = [
      '-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete')
    end
    security_baseline_auditd['delete'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep scope')
    expected = [
      '-w /etc/sudoers -p wa -k scope',
      '-w /etc/sudoers.d -p wa -k scope',
    ]
    security_baseline_auditd['scope'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep actions')
    expected = [
      '-w /var/log/sudo.log -p wa -k actions',
    ]
    security_baseline_auditd['actions'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('auditctl -l | grep "modules$"')
    expected = [
      '-w /sbin/insmod -p x -k modules',
      '-w /sbin/rmmod -p x -k modules',
      '-w /sbin/modprobe -p x -k modules',
    ]
    if arch == 'x86_64'
      expected.push('-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules')
    else
      expected.push('-a always,exit -F arch=b32q -S init_module,delete_module -F key=modules')
    end
    security_baseline_auditd['modules'] = check_values(val, expected)

    val = Facter::Core::Execution.exec('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1')
    security_baseline_auditd['immutable'] = if val.empty? || val.nil?
                                              false
                                            elsif val == '-e 2'
                                              true
                                            else
                                              false
                                            end

    security_baseline_auditd
  end
end
