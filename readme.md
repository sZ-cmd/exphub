## To be used for legitimate, authorised pentesting only.
DISCLAIMER: ANY MALICIOUS USE OF THE CONTENTS FROM THIS ARTICLE 
WILL NOT HOLD THE AUTHOR RESPONSIBLE, THE CONTENTS ARE SOLELY FOR
EDUCATIONAL PURPOSE & LEGITIMATE AUTHORISED PENTESTING.
## CN - EN translation.

# Notice
~~ After all, I still feel that each individual script for each vulnerability is very inconvenient, so we can integrate all the poc and exp scripts together, which can be one-click scanning + vulnerability exploitation. Because of the recent integration, exphub has not been updated for a long time. The current integrated version is nearing completion and will be released in October (after the holiday), so stay tuned~~
Has been released ---> https://github.com/zhzyker/vulmap

# Exphub
Exphub[Exploit Script Library] 
Currently, exploit scripts including Webloigc, Struts2, Tomcat, and Drupal are all script files available for pro-testing. We will try our best to complete the instructions for all script files, and update high-risk and easy-to-use exploit scripts first.
Some scripts or files are collected, if there is a copyright request, please contact us to change it
Geese: 219291257
bilibili: https://space.bilibili.com/64648363
 
Last update: 2020/11/07, the latest addition **cve-2020-14882_rce.py**

# Readme
Exphub includes a variety of files with different names, types, formats, and suffixes. These files can be roughly divided into [Vulnerability Verification Script], [Exploit Script], [Remote Command Execution Script], [Shell Interactive Script], [Webshell Upload Script ]
Example script file: cve-1111-1111_xxxx.py

Script file type [xxxx]:
-cve-1111-1111_**poc** [Vulnerability Verification Script] Only check whether the verification vulnerability exists
-cve-1111-1111_**exp** [Exploit Script] For example, general vulnerabilities such as file inclusion, arbitrary file reading, etc., please refer to the specific use of each script [Use]
-cve-1111-1111_**rce** [Remote Command Execution Script] The command executes the exploit script and cannot be interactive
-cve-1111-1111_**cmd** [Remote Command Execution Script] Command to execute the exploit script, no interaction
-cve-1111-1111_**shell** [Remote command execution script] Rebound shell directly, or provide a simple interactive shell to transfer commands, basic interaction
-cve-1111-1111_**webshell** [Webshell upload script] Automatically or manually upload Webshell

Script file format [py]:
-cve-xxxx.**py** Python files, including py2 and py3, refer to the instructions for which file is which version (you can see it after execution), py2.7 and py3.7 are recommended
-cve-xxxx.**sh** Shell script, which needs to be run in a Linux environment, see instructions immediately after execution, no release requirements
-cve-xxxx.**jar** Java files, the execution method is `java -jar cve-xxxx.jar`, Java1.8.121 is recommended
-cve-xxxx.**php** PHP file, just use the `php` command to execute
-cve-xxxx.**txt** Vulnerability Payload that cannot be written into an executable file will be directly written as txt text, and how to use it is recorded in the text (usually GET/POST requests)

## Weblogic
[**cve-2014-4210_ssrf_scan.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF scan intranet port utilization script [[Use]](https:/ /freeerror.org/d/483)
[**cve-2014-4210_ssrf_redis_shell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic SSRF vulnerability intranet redis unauthorized getshell script [[use]](https ://freeerror.org/d/483)

[**cve-2017-3506_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat remote command execution vulnerability detection script [[Use]](https ://freeerror.org/d/468)
[**cve-2017-3506_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat remote command execution vulnerability exploit, upload Webshell[[Use]] (https://freeerror.org/d/468)
[**cve-2017-10271_poc.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder deserialization vulnerability [[Use]](https: //freeerror.org/d/460)
[**cve-2017-10271_webshell.jar**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic wls-wsat XMLDecoder deserialization exploit script [[Use]]( https://freeerror.org/d/460)
[**cve-2018-2628_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic WLS Core Components deserialization command execution vulnerability verification script [[Use]] (https://freeerror.org/d/464)
[**cve-2018-2628_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic WLS Core Components command execution vulnerability upload Webshell script [[Use]](https ://freeerror.org/d/464)
[**cve-2018-2893_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS core component deserialization vulnerability detection script
[**cve-2018-2893_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic WLS core component deserialization exploit script
[**cve-2018-2894_poc_exp.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic arbitrary file upload vulnerability detection + exploitation
[**cve-2019-2618_webshell.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic arbitrary file upload vulnerability (requires account password) [[use]](https ://freeerror.org/d/469)
[**cve-2020-2551_poc.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) Weblogic IIOP deserialization vulnerability detection script
[**cve-2020-2555_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic GIOP protocol deserialization remote command execution
[**cve-2020-2883_cmd.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic T3 protocol deserialization remote command execution
[**cve-2020-14882_rce.py**](https://github.com/zhzyker/exphub/blob/master/weblogic/) WebLogic console unauthorized command execution

## Shiro
[**shiro-1.2.4_rce.py**](https://github.com/zhzyker/exphub/tree/master/shiro) Apache Shiro rememberMe <1.2.4 RCE exploit script

## Solr
[**cve-2017-12629_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr remote command execution script
[**cve-2019-0193_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr DataImportHandler remote code execution exploit script
[**cve-2019-17558_cmd.py**](https://github.com/zhzyker/exphub/tree/master/solr) Apache Solr Velocity remote code execution exploit script[[Video_Bilibili]](https ://www.bilibili.com/video/BV1jf4y12749) [[Video_YouTube]](https://www.youtube.com/watch?v=WP81oOl2AgU)

## Spring
[**cve-2018-1273_cmd.py**](https://github.com/zhzyker/exphub/tree/master/spring) Spring remote code execution exploit script

## Struts2
[**struts2-032_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 method arbitrary code execution vulnerability GetShell exploit script (CVE-2016-3081)
[**struts2-032_poc.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 method arbitrary code execution vulnerability detection script (CVE-2016-3081)
[**struts2-045_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Jakarta Multipart parser plugin remote command execution exploit script 1 (CVE-2017-5638)[ [Use]](https://freeerror.org/d/490)
[**struts2-045-2_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Jakarta Multipart parser plugin remote command execution exploit script 2 (CVE-2017-5638 )[[Use]](https://freeerror.org/d/490)
[**struts2-052_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 REST plug-in remote code execution exploit script (CVE-2017-9805)
[**struts2-052_webshell.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 REST plug-in remote code execution vulnerability upload Webshell script (CVE-2017-9805)
[**struts2-053_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Freemarker tag remote execution command exploit script (CVE-2017-12611)
[**struts2-057_cmd.py**](https://github.com/zhzyker/exphub/blob/master/struts2) Struts2 Namespace remote code execution exploit script (CVE-2018-11776)

## Tomcat
[**cve-2017-12615_cmd.py**](https://github.com/zhzyker/exphub/blob/master/tomcat/) Tomcat remote code execution exploit script [[Use]](https:// freeerror.org/d/411)
[**cve-2020-1938_exp.py**](https://github.com/zhzyker/exphub/blob/master/tomcat/) Tomcat Ghost Cat arbitrary file reading exploit script [[Use]](https ://freeerror.org/d/484)

## Drupal
[**cve-2018-7600_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal Drupalgeddon 2 remote code execution exploit script [Use]](https:/ /freeerror.org/d/426)
[**cve-2018-7600_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) This script can detect CVE-2018-7602 and CVE-2018-7600
[**cve-2018-7602_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal kernel remote code execution exploit script (requires account password)
[**cve-2018-7602_poc.py**](https://github.com/zhzyker/exphub/tree/master/drupal) This script can detect CVE-2018-7602 and CVE-2018-7600
[**cve-2019-6340_cmd.py**](https://github.com/zhzyker/exphub/tree/master/drupal) Drupal 8.x REST RCE remote code execution exploit script

## F5
[**cve-2020-5902_file.py**](https://github.com/zhzyker/exphub/tree/master/f5) F5 BIG-IP arbitrary file reading

## Nexus
[**cve-2019-7238_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 remote code execution exploit script
[**cve-2020-10199_poc.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 remote command execution vulnerability detection script [[Video_Bilibili]] (https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[Video_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)
[**cve-2020-10199_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Repository Manager 3 remote code execution vulnerability (can be echoed)[[Video_ Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[Video_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)
[**cve-2020-10204_cmd.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus Manager 3 remote command execution exploit script (no echo)[[video _Bilibili]](https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[Video_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)
[**cve-2020-11444_exp.py**](https://github.com/zhzyker/exphub/tree/master/nexus/) Nexus 3 arbitrary modification of admin password unauthorized exploit script [[Video_Bilibili]] (https://www.bilibili.com/video/BV1uQ4y1P7MA/) [[Video_YouTube]](https://www.youtube.com/watch?v=ocQMDYxTMKk)

## Jboss
[**cve-2017-12149_poc.py**](https://github.com/zhzyker/exphub/tree/master/jboss) JBoss 5.x/6.x deserialization remote code execution vulnerability verification script
[**cve-2017-12149_cmd.py**](https://github.com/zhzyker/exphub/tree/master/jboss) JBoss 5.x/6.x deserialization remote code execution exploit script
