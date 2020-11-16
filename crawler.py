import os, sys, time, queue, shutil, socket, threading, requests, dns.resolver, re
import urllib.robotparser
from random import randint
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from subprocess import DEVNULL, STDOUT, check_call
import random
from itertools import islice, cycle

cache = set()
blacklist = set()
a = list()
q = queue.Queue()
dnsCache = dict()
agent = "RIWEB_CRAWLER"
#agent = "wooBot"
rules = dict()
noDns = None

regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

def sendDNSRequest(domeniu):
    value= randint(0,10)
    if domeniu.startswith("www."):
        domeniu=domeniu[4:]
    check_call(['nslookup ', domeniu], stdout=DEVNULL, stderr=STDOUT)
    msj = bytearray(12+len(domeniu)+6)
    msj[1]=0xFF&value+1
    msj[5]=0x01
    sendID = (((0xFF) & msj[0]) << 8) | (0xFF & msj[1])
    labels = domeniu.split(".")
    idx = 12
    for i in labels:
        msj[idx]=len(i)&0xFF
        idx=idx+1
        for j in i:
            msj[idx]=ord(j)
            idx=idx+1
    msj[idx]=0
    msj[idx+2]=0x1
    msj[idx+4]=0x1
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address= ("192.168.1.254",53)
    sent= sock.sendto(msj,server_address)
    response = bytearray(512)
    response, server = sock.recvfrom(512)
    sock.close()
    recivID=(((0xFF) & response[0]) << 8) | (0xFF & response[1])
    if recivID == sendID:
        if (response[3] & 0x0F) == 0x00:
            pass
        else:
            errorCode = response[3] & 0x0F;
            print("DNS request failed with the r-code "+str(errorCode)) 
            return
    noResp = (((0xFF) & response[6]) << 8) | (0xFF & response[7])
    noAuth = (((0xFF) & response[8]) << 8) | (0xFF & response[9])
    noRec = (((0xFF) & response[10]) << 8) | (0xFF & response[11])
    index = 12 + len(domeniu) + 6;
    respDomain = getDNS(response, index)[:-1]
    if (response[index] & 0xFF) < 192:
        index = index + len(respDomain) + 1
    else:
        index = index + 1
    index = index + 1
    MSB = response[index]
    index = index + 1
    LSB = response[index]
    recordType = (((0xFF) & MSB) << 8) | (0xFF & LSB)
    index = index+1
    MSB = response[index]
    index = index+1
    LSB = response[index]
    recordClass = (((0xFF) & MSB) << 8) | (0xFF & LSB)  
    index = index+1    
    b3 = response[index]
    index = index+1
    b2 = response[index]
    index = index+1
    b1 = response[index]
    index = index+1
    b0 = response[index]
    TTL = ((0xFF & b3) << 24) | ((0xFF & b2) << 16) | ((0xFF & b1) << 8) | (0xFF & b0)
    ttl = TTL+time.time()
    index = index+1
    MSB = response[index]
    index = index+1
    LSB = response[index]
    dataLen = (((0xFF) & MSB) << 8) | (0xFF & LSB)
    word = ""
    ipv4 = ""
    ipv6 = ""
    if dataLen == 4 and recordType == 1:
        for i in range(dataLen):
            index = index+1
            word =word + str(response[index]& 0xFF) + "."
        ipv4=word[:-1]
    elif dataLen == 16 and recordType == 28:
        for i in range(dataLen):
            index = index+1
            word =word + str(response[index]& 0xFF) + "."
        ipv6=word[:-1]
    elif recordType == 2:
        nsName = getDNS(index, response)
        index = index + len(nsName)
    elif (recordType == 5):
        canonicalName = getDNS(index, response)
        index = index + len(canonicalName)
    return ipv4, ttl 
    
def getDNS(resp, idx):
    if (resp[idx]& 0xFF) == 0x0:
        return ""
    if (resp[idx] & 0xFF) >= 192:
        newIdx=((resp[idx] & 0x3F) << 8) | (resp[idx+1] & 0xFF)
        return getDNS(resp, newIdx)
    i=(resp[idx] & 0xFF)+1
    word =""
    for j in range(1, i):
        word =word + chr(resp[idx+j])
    idx = idx + i
    return word + "." + getDNS(resp, idx)

def getPage(url):
    protocol = url[:url.find(':')+3]
    host = url[url.find(':')+3:].split('/')[0]
    resource =url[url.find(':')+3+len(host):]
    if host in dnsCache:
        if dnsCache[host]["ttl"] - time.time() <0:
            cacheDNS(host)
    else:
        cacheDNS(host)
    headers = {
    'User-Agent': agent,
    'Host': host,
    'Connection':'Close'
    }
    session = requests.session()
    response= None
    if "https" in protocol:
        response=session.get(protocol+host+resource,headers=headers,allow_redirects=False)
    else:
        response=session.get(protocol+dnsCache[host]["ip"]+resource,headers=headers,allow_redirects=False) #socket.connect  
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")      
        return soup
    elif str(response.status_code).startswith("4") or str(response.status_code).startswith("5"):
        blacklist.add(url)
    elif str(response.status_code).startswith("3"):
        contor = 0
        for redirect in session.resolve_redirects(response, response.request):
            if str(redirect.status_code).startswith("4") or str(redirect.status_code).startswith("5"):
                blacklist.add(url)
                break
            elif redirect.status_code == 200:
                soup = BeautifulSoup(redirect.text, "html.parser")      
                return soup
            if contor > 9:
                blacklist.add(url)
                break
            contor += 1    
    return        
                        
def printMeta(soup):
    index = True
    follow = True
    for tag in soup.find_all("meta"):
        if tag.get("name", None) == "robots":          
            if "all" in tag.get("content", None):
                pass
            if "index" in tag.get("content", None).lower()  or "nofollow" in tag.get("content", None).lower():
                follow=False
            if "noindex" in tag.get("content", None).lower() or "follow" in tag.get("content", None).lower():
                index=False
            if "none" in tag.get("content", None):   
                index=False
                follow=False
    return index, follow           

def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    num_active = len(iterables)
    nexts = cycle(iter(it).__next__ for it in iterables)
    while num_active:
        try:
            for next in nexts:
                yield next()
        except StopIteration:
            num_active -= 1
            nexts = cycle(islice(nexts, num_active))
          
def findLinks(url, soup):
    for link in soup.find_all('a'):
        if link.get("href", None) and "#" not in link.get("href", None) and "?" not in link.get("href", None):
            if not urljoin(url,link.get("href")) in cache and not link.get("href").startswith("http"):
                if len(cache) < 100 * noDns and re.match(regex, urljoin(url,link.get("href"))) :
                    cache.add(urljoin(url,link.get("href")))
                    a.append(urljoin(url,link.get("href")))               
                        
def savePage(text, url):
    if not os.path.exists(url):
        os.makedirs(url)
    if url.endswith(".html"):
        with open(url+"/"+os.path.basename(url).split(".")[0]+".txt", "w",encoding="utf-8") as w:
            w.write(text)
    else:        
        with open(url+"domain.txt", "w",encoding="utf-8") as w:
            w.write(text)
     
def crawl(dnsList):
    global noDns, a    
    noDns=len(dnsList) 
    for dns in dnsList:
        protocol=dns[:dns.find(":")+3]
        filepath=dns[dns.find(":")+3:]
        host = filepath.split('/')[0]
        cacheDNS(host)
        global rules
        rules[host] = getRules(protocol, host)
        if os.path.exists(host):
            shutil.rmtree(host)
        work(dns)
    flag = True        
    while len(a) > 0: 
        print("\n")
        try:
            v = a.index(next(x for x in a if "python.org" in x))
            b = a.index(next(x for x in a if "riweb.tibeica.com" in x))
            x= max(v,b)
            z = list(roundrobin(a[:x],a[x:]))
            word = z[-1][0:15]
            index = 0
            for i in z[-2::-1]:
                if word in i:
                    index-=1
                else:
                    break
            a=z[index:]
            z = z[:index]   
            [q.put(i) for i in z]
        except:
            [q.put(i) for i in a]
            a.clear()
     
        if flag == True:
            numThreads = noDns
            try:
                if (sys.argv[1] != None and sys.argv[1].isdecimal()):
                    numThreads = int(sys.argv[1])
            except:
                pass
            for _ in range(numThreads):
                t = threading.Thread(target=func,daemon=True)
                t.start()
            flag = False    
        else:
            pass
        q.join()
        
        
    
            
def func():
    while True:
        url=q.get()
        work(url)
        q.task_done()
                  
def work(url):
    time.sleep(0.25)
    print(str(threading.current_thread().name)+":"+url)
    protocol=url[:url.find(":")+3]
    filepath=url[url.find(":")+3:]
    host= filepath.split('/')[0]
    if os.path.exists(filepath):
        return
    if host not in rules:
        rules[host] = getRules(protocol, host)
    if rules[host].can_fetch(agent,url):
        page = getPage(url)
        if page != None:
            index, follow = printMeta(page)
            if index == True:
                savePage(page.get_text(), filepath) 
            if follow == True:
                findLinks(url, page)         
                                                            
def cacheDNS(host):
    try:
        ip, ttl = sendDNSRequest(host)
    except:
        ip = socket.gethostbyname(host)
        ttl = dns.resolver.resolve(host).rrset.ttl + time.time()
    dnsCache[host]={"ip":ip,"ttl":ttl}
    
def getRules(protocol,host):
    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(protocol+host+"/robots.txt")
    robots.read()
    return robots    
   
def main():
    dnsList={
        "http://riweb.tibeica.com/crawl/",
        "https://www.python.org/"   
    }
    start = time.time()
    crawl(dnsList)
    end = time.time()
    print("Elapsed time: "+str(int(end - start))+" s")
            
if __name__=="__main__":
    main()