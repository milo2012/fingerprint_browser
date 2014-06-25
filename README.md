**Description**
- This tool identifies the version of the browser and browser plugins (java/flash/reader) and exploits them via Metasploit.
- The target browser also reports back the plugins and their versions back to the tool.

**Requirements**
- Python2.7
- MITMProxy
- Ettercap / Responder / Intercepter-NG

**Installation Steps**
- Install MITMProxy 0.9.1 https://github.com/mitmproxy/mitmproxy/archive/v0.9.1.zip
- git clone https://github.com/milo2012/fingerprint_browser.git
- cd fingerprint_browser
- python2.7 webserver.py 
- Run the ettercap ARP spoofing command as shown on screen

The javascript code for the plugins version detection is from https://browserscan.rapid7.com/scanme.
Thank you for the awesome code.

![alt text](https://raw.githubusercontent.com/milo2012/fingerprint_browser/master/screenshot.jpg "Screenshot of Script")

Demo video available at [http://youtu.be/m8Yb-d7kzwQ]

**To Do Wish Lists**
- Replace documents (pdf,word documents) on the fly with infected version via ARP spoofing
- Inject infected documents into browsers via WPAD 
