***Installation Tips***
apt-get install libffi-dev

cd /tmp

wget https://pypi.python.org/packages/source/s/setuptools/setuptools-5.2.tar.gz --no-check-certificate

tar xvfz setuptools-5.2.tar.gz

cd setuptools-5.2

python2.7 setup.py install

cd /tmp

wget https://pypi.python.org/packages/source/p/pip/pip-1.5.6.tar.gz --no-check-certificate

tar xvfz pip-1.5.6.tar.gz

cd pip-1.5.6

python2.7 setup.py  install

cd /tmp

wget https://github.com/mitmproxy/mitmproxy/archive/v0.9.1.zip -O mitmproxy-0.9.1.zip

wget https://github.com/mitmproxy/netlib/archive/v0.9.1.zip -O netlib-0.9.1.zip

unzip mitmproxy-0.9.1.zip

unzip netlib-0.9.1.zip

cd  mitmproxy-0.9.1

pip2.7 install PIL --allow-external PIL --allow-unverified PIL

pip2.7 install -r requirements.txt

- Edit libmproxy/platform/__init__.py 
- Replace the file with the below
```python
import sys
resolver = None
if sys.platform == "linux3":
    import linux
    resolver = linux.Resolver
if sys.platform == "linux2":
    import linux
    resolver = linux.Resolver
elif sys.platform == "darwin":
    import osx
    resolver = osx.Resolver
```

python2.7 setup.py install 

cd ..

cd netlib-0.9.1

python2.7 setup.py install 
