Shellshocker - Repository of "Shellshock" Proof of Concept Code
=================

Collection of Proof of Concepts and Potential Targets for #ShellShocker

Wikipedia Link: https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#CVE-2014-7186_and_CVE-2014-7187_Details

Please submit a pull request if you have more links or other resources

**Speculation:(Non-confirmed possibly vulnerable)** 

+ XMPP(ejabberd)
+ Mailman
+ MySQL
+ NFS
+ Bind9
+ Juniper Google Search`inurl:inurl:/dana-na/auth/url_default/welcome.cgi`
  + via: https://twitter.com/notsosecure/status/516132301025984512
  + via: http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10648&actp=RSS
+ Cisco Gear
  + via: http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash

**If you know of PoCs for any of these, please submit an issue or pull request with a link.**

## Command Line (Linux, OSX, and Windows via Cygwin)

### CVE-2014-6271
+`env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c id`

### CVE-2014-7169
_will create a file named echo in cwd with date in it, if vulnerable_
+ `env X='() { (a)=>\' bash -c "echo date"; cat echo`

### CVE-2014-7186
+ `bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"`

### CVE-2014-7187
+ `(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno"`

### CVE-2014-6278
+

### CVE-2014-6277
+ 


## IBM z/OS - 
+ http://mainframed767.tumblr.com/post/98446455927/bad-news-is-it-totally-works-in-bash-on-z-os-and

## HTTP
+ Metasploit Exploit Module Apache MOD_CGI - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/apache_mod_cgi_bash_env_exec.rb
+ HTTP Header Polution by @irsdl - http://pastebin.com/QNkf7dYS
+ HTTP CGI-BIN - http://pastebin.com/166f8Rjx
+ cPanel - http://blog.sucuri.net/2014/09/bash-vulnerability-shell-shock-thousands-of-cpanel-sites-are-high-risk.html
+ F5 - https://twitter.com/securifybv/status/515035044294172673
  + https://twitter.com/securifybv/status/515035044294172673/photo/1
  + https://twitter.com/avalidnerd/status/515056463589675008
    + https://twitter.com/avalidnerd/status/515056463589675008/photo/1
+ Invisiblethreat.ca - https://www.invisiblethreat.ca/2014/09/cve-2014-6271/
+ Commandline version - https://gist.github.com/mfadzilr/70892f43597e7863a8dc
+ User-Agent based walkthrough with LiveHTTPHeaders - http://www.lykostech.net/lab-time-exploiting-shellshock-bash-bug-virtual-server/
+ User-Agent based walkthrough with Burp - http://oleaass.com/shellshock-proof-of-concept-reverse-shell/
+ User-Agent via Curl with test server - http://shellshock.notsosecure.com/
+ User-Agent based but supports Tor and Socks5 (Python) - https://github.com/lnxg33k/misc/blob/master/shellshock.py
+ User-Agent based in Ruby - https://github.com/securusglobal/BadBash

## DHCP
+ Trusted sec exploitation via Tftpd32 - https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/
+ Metasploit Exploit Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/dhcp/bash_environment.rb
+ Metasploit Auxiliary Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/dhclient_bash_env.rb
+ Perl Script - http://pastebin.com/S1WVzTv9

## SSH
+ Stack Overflow - http://unix.stackexchange.com/questions/157477/how-can-shellshock-be-exploited-over-ssh
+ SSH ForcedCommand - https://twitter.com/JZdziarski/status/515205581226123264
  + https://twitter.com/JZdziarski/status/515205581226123264/photo/1
+ SendEnv: `LC_X='() { :; }; echo vulnerable' ssh foo@bar.org -o SendEnv=LC_X`

## OSX
+ Priv Escalation via VMware Fusion - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/osx/local/vmware_bash_function_root.rb

## SIP
+ SIP Proxies: https://github.com/zaf/sipshock


## Qmail
+ Detailed walkthrough - http://marc.info/?l=qmail&m=141183309314366&w=2
+ Tweet from @ymzkei5 - http://twitter.com/ymzkei5/status/515328039765307392
  + http://twitpic.com/ec3615
  + http://twitpic.com/ec361o

## FTP
+ Pure-FTPd: https://gist.github.com/jedisct1/88c62ee34e6fa92c31dc


## TMNT
+ https://twitter.com/SynAckPwn/status/514961810320293888/photo/1

## Hand
+ Via @DJManilaIce - http://pastie.org/9601055
```
user@localhost:~$ env X='() { (a)=>\' /bin/bash -c "shellshocker echo -e \"           __ __\n          /  V  \ \n     _    |  |   |\n    / \   |  |   |\n    |  |  |  |   |\n    |  |  |  |   |\n    |  |__|  |   |\n    |  |  \  |___|___\n    |  \   |/        \ \n    |   |  |______    |\n    |   |  |          |\n    |   \__'   /     |\n    \        \(     /\n     \             /\n      \|            |\n\""; cat shellshocker
/bin/bash: X: line 1: syntax error near unexpected token `='
/bin/bash: X: line 1: `'
/bin/bash: error importing function definition for `X'
           __ __
          /  V  \ 
     _    |  |   |
    / \   |  |   |
    |  |  |  |   |
    |  |  |  |   |
    |  |__|  |   |
    |  |  \  |___|___
    |  \   |/        \ 
    |   |  |______    |
    |   |  |          |
    |   \__'   /     |
    \        \(     /
     \             /
      \|            |

```
