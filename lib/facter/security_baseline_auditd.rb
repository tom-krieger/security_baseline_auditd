# frozen_string_literal: true

# security_baseline_auditd.rb
# Gather facts around auditd

Facter.add('security_baseline_auditd') do
  confine osfamily: 'RedHat'
  setcode do
    security_baseline_auditd = {}
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
    #
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

    security_baseline_auditd
  end
end
