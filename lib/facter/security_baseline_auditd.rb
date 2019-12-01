# frozen_string_literal: true

require 'facter/security_baseline_auditd/redhat/secutity_baseline_auditd_redhat'
require 'pp'

# security_baseline_auditd.rb
# Gather facts around auditd

Facter.add(:security_baseline_auditd) do
  os = Facter.value(:osfamily).downcase
  distid = Facter.value(:lsbdistid)
  release = Facter.value(:operatingsystemmajrelease)
  ret = {}
  setcode do
    case os
    when 'redhat'
      ret = security_baseline_auditd_redhat(os, distid, release)
    when 'debian'
      ret = security_baseline_auditd_debian(os, distid, release)
    when 'suse'
      ret = security_baseline_auditd_sles(os, distid, release)
    end
  end

  ret
end
