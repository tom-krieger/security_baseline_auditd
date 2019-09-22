# @summary 
#    Ensure kernel module loading and unloading is collected (Scored)
#
# Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), 
# rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, 
# as well as some other features) control loading and unloading of modules. The init_module (load a module) 
# and delete_module (delete a module) system calls control loading and unloading of modules. Any execution 
# of the loading and unloading module programs and system calls will trigger an audit record with an 
# identifier of "modules".
#
# Rationale:
# Monitoring the use of insmod , rmmod and modprobe could provide system administrators with evidence that 
# an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. 
# Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting 
# to use a different program to load and unload modules.
#
# @example
#   class { 'security_baseline_auditd::rules::modules':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
class security_baseline_auditd::rules::modules (
  Boolean $enforce,
  String $message = '',
  String $log_level = 'info',
) {
  require 'auditd'

  if($enforce) {

    if($facts['security_baseline_auditd']['modules'] == false) {
      auditd::rule { 'watch modules rule 1':
        content => '-w /sbin/insmod -p x -k modules',
      }
      auditd::rule { 'watch modules rule 2':
        content => '-w /sbin/rmmod -p x -k modules',
      }
      auditd::rule { 'watch modules rule 3':
        content => '-w /sbin/modprobe -p x -k modules',
      }
      if($facts['architecture'] == 'x86_64') {
        auditd::rule { 'watch modules rule 4':
          content => '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules',
        }
      } else {
        auditd::rule { 'watch modules rule 4':
          content => '-a always,exit -F arch=b32 -S init_module -S delete_module -k modules',
        }
      }
    }
  } else {
    if($facts['security_baseline_auditd']['mounts'] == false) {
      echo { 'auditd-mounts':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

      ::security_baseline::logging { 'auditd-mounts':
        rulenr    => 'auditd',
        rule      => 'auditd',
        desc      => 'Ensure kernel module loading and unloading is collected (Scored)',
        level     => $log_level,
        msg       => 'Auditd has no rule to collect kernel module loading and unloading events.',
        rulestate => 'not compliant',
      }
    }
  }
}
