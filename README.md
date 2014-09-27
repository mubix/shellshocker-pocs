shellshocker-pocs
=================

Collection of Proof of Concepts and Potential Targets for #ShellShocker

Please submit a pull request if you have more links or other resources

## Command Line
+ `env x='() { :;}; echo vulnerable' bash -c 'echo hello'`

## HTTP
+ Metasploit Exploit Module Apache MOD_CGI - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/apache_mod_cgi_bash_env_exec.rb
+ HTTP Header Polution by @irsdl - http://pastebin.com/QNkf7dYS
+ HTTP CGI-BIN - http://pastebin.com/166f8Rjx
+ 

## DHCP
+ Trusted sec exploitation via Tftpd32 - https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/
+ Metasploit Exploit Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/dhcp/bash_environment.rb
+ Metasploit Auxiliary Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/dhcp.rb
+ Perl Script - http://pastebin.com/S1WVzTv9

## SSH
+ Stack Overflow - http://unix.stackexchange.com/questions/157477/how-can-shellshock-be-exploited-over-ssh

## OSX
+ Priv Escalation via VMware Fusion - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/osx/local/vmware_bash_function_root.rb

## SIP
+ SIP Proxies: https://github.com/zaf/sipshock


## Qmail
+ Tweet from @ymzkei5 - http://twitter.com/ymzkei5/status/515328039765307392
  + http://twitpic.com/ec3615
  + http://twitpic.com/ec361o
