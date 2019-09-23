require 'spec_helper'

describe 'security_baseline_auditd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline_auditd' => {
            'max_log_file' => 32,
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
