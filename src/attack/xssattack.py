#!/usr/bin/env python
import random
import re
from net import BeautifulSoup
from attack import Attack
from vulnerability import Vulnerability

class XSSAttack(Attack):
  """
  This class implements a cross site scripting attack
  """

  # magic strings me must see to be sure script is vulnerable to XSS
  # payloads must be created on those paterns
  script_ok=[
      "alert('__XSS__')",
      "alert(\"__XSS__\")",
      "String.fromCharCode(0,__XSS__,1)"
      ]

  # simple payloads that doesn't rely on their position in the DOM structure
  # payloads injected after closing a tag aatibute value (attrval) or in the
  # content of a tag (text node like beetween <p> and </p>)
  # only trick here must be on character encoding, filter bypassing, stuff like that
  # form the simplest to the most complex, Wapiti will stop on the first working
  independant_payloads = []

  xss_history={} # will be removed later
  HTTP=None

  # two dict for permanent XSS scanning
  GET_XSS={}
  POST_XSS={}

  CONFIG_FILE = "xssPayloads.txt"

  def __init__(self,HTTP,xmlRepGenerator):
    Attack.__init__(self,HTTP,xmlRepGenerator)
    self.independant_payloads = self.loadPayloads(self.CONFIG_DIR+"/"+self.CONFIG_FILE)

  def attackGET(self,page,dict,attackedGET):
    # page est l'url de script
    # dict est l'ensembre des variables et leurs valeurs
    if dict=={}:
      # TODO for QUERYSTRING
      err=""
      code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
      url=page+"?"+code
      data=self.HTTP.send(url).getPage()
    else:
      for k in dict.keys():
        err=""
        tmp=dict.copy()
        tmp[k]="__XSS__"
        url=page+"?"+self.HTTP.uqe(tmp)
        if url not in attackedGET:
          attackedGET.append(url)
          # genere un identifiant unique a rechercher ensuite dans la page
          code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
          tmp[k]=code
          url=page+"?"+self.HTTP.uqe(tmp)
          self.GET_XSS[code]=url
          data=self.HTTP.send(url).getPage()
          # on effectue une recherche rapide sur l'indetifiant
          if data.find(code)>=0:
            # identifiant est dans la page, il faut determiner ou
            if self.findXSS(data,page,tmp,k,code):
              break

  # will be erased when totally replaced by attackGET
  def old_attackXSS(self,page,dict):
    if dict=={}:
      err=""
      tab=[page,"QUERYSTRING"]
      xss_hash=hash(str(tab))
      self.xss_history[xss_hash]=tab
      payload="<script>var XSS"
      payload+=str(xss_hash).replace("-","_")
      payload+="</script>"
      url=page+"?"+payload
      if url not in attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        if data.find(payload)>=0:
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url,payload,"XSS (QUERY_STRING)")
          print "XSS (QUERY_STRING) in",page
          print "\tEvil url:",url
        else:
          if code==500:
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload,"500 HTTP Error code")
            print "500 HTTP Error code with"
            print "\tEvil url:",url
        attackedGET.append(url)
    for k in dict.keys():
      err=""
      tmp=dict.copy()
      tab=[page,k]
      xss_hash=hash(str(tab))
      self.xss_history[xss_hash]=tab
      payload="<script>var XSS"
      payload+=str(xss_hash).replace("-","_")
      payload+=";</script>"
      tmp[k]=payload
      url=page+"?"+self.HTTP.uqe(tmp)
      if url not in attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        if data.find(payload)>=0:
          if self.color==0:
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "XSS ("+k+")")
            print "XSS ("+k+") in",page
            print "\tEvil url:",url
          else:
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "XSS: "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
            print "XSS",":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
        else:
          if code==500:
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "500 HTTP Error code")
            print "500 HTTP Error code with"
            print "\tEvil url:",url
        attackedGET.append(url)

  def attackPOST(self,form,attackedPOST):
    headers={"Accept": "text/plain"}
    page=form[0]
    params=form[1]
    for k in params.keys():
      tmp=params
      log=params.copy()

      log[k]="__XSS__"
      if (page,log) not in attackedPOST:
        attackedPOST.append((page,log))
        code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
        tmp[k]=code
        # will only memorize the last used payload (working or not) but the code will always be the good
        self.POST_XSS[code]=[page,tmp,form[2]]
        data=self.HTTP.send(page,self.HTTP.uqe(tmp),headers).getPage()
        # rapid search on the code to check injection
        if data.find(code)>=0:
          # found, now study where and what is possible
          if self.findXSS(data,page,tmp,k,code,form[2]):
            break


  def permanentXSS(self,url):
    headers={"Accept": "text/plain"}
    data=self.HTTP.send(url).getPage()
    for code in self.GET_XSS.keys():
      if data.find(code)>=0:
        # we where able to inject the ID but will we be able to inject javascript?
        for xss in self.independant_payloads:
          attack_url=self.GET_XSS[code].replace(code,xss.replace("__XSS__",code))
          self.HTTP.send(attack_url)
          dat=self.HTTP.send(url).getPage()
          if self.validXSS(dat,code):
            print "Found permanent XSS in",url,"with",attack_url
            self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,url,"",
                            "Found permanent XSS in "+url+" with "+attack_url)
            break

    for code in self.POST_XSS.keys():
      if data.find(code)>=0:
        for k,v in self.POST_XSS[code][1].items():
          if v==code:
            tmp=self.POST_XSS[code][1].copy()
            for xss in self.independant_payloads:
              tmp[k]=xss.replace("__XSS__",code)
              self.HTTP.send(self.POST_XSS[code][0],self.HTTP.uqe(tmp),headers)
              dat=self.HTTP.send(url).getPage()
              if self.validXSS(dat,code):
                self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,url,"",
                            "Found permanent XSS attacked by "+self.POST_XSS[code][0]+
                            " with field "+self.HTTP.uqe(self.POST_XSS[code][1]))
                print "Found permament XSS in",self.POST_XSS[code][0]
                print "  attacked by",self.POST_XSS[code][2],"with fields",self.HTTP.uqe(tmp)
                break

  # type/name/tag ex: attrval/img/src
  def study(self,obj,parent=None,keyword="",entries=[]):
    #if parent==None:
    #  print "Keyword is:",keyword
    if str(obj).find(keyword)>=0:
      if isinstance(obj,BeautifulSoup.Tag):
        if str(obj.attrs).find(keyword)>=0:
          for k,v in obj.attrs:
            if v.find(keyword)>=0:
              #print "Found in attribute value ",k,"of tag",obj.name
              entries.append({"type":"attrval","name":k,"tag":obj.name})
            if k.find(keyword)>=0:
              #print "Found in attribute name ",k,"of tag",obj.name
              entries.append({"type":"attrname","name":k,"tag":obj.name})
        elif obj.name.find(keyword)>=0:
          #print "Found in tag name"
          entries.append({"type":"tag","value":obj.name})
        else:
          for x in obj.contents:
            self.study(x,obj,keyword,entries)
      elif isinstance(obj,BeautifulSoup.NavigableString):
        if str(obj).find(keyword)>=0:
          #print "Found in text, tag", parent.name
          entries.append({"type":"text","parent":parent.name})

  def validXSS(self,page,code):
    soup=BeautifulSoup.BeautifulSoup(page)
    for x in soup.findAll("script"):
      #if x.string != None: print "-"+x.string+"-"
      if x.string!=None and x.string in [t.replace("__XSS__",code) for t in self.script_ok]:
        return True
      elif x.has_key("src"):
        if x["src"]=="http://__XSS__/x.js".replace("__XSS__",code):
          return True
    return False



  # GET and POST methods here
  def findXSS(self,data,page,args,var,code,referer=""):
    headers={"Accept": "text/plain"}
    params=args.copy()
    soup=BeautifulSoup.BeautifulSoup(data) # il faut garder la page non-retouchee en reserve...
    e=[]
    self.study(soup,keyword=code,entries=e)
    url=page
    for elem in e:
      payload=""
      # traiter chaque entree au cas par cas
      # on quitte a la premiere entree exploitable

      # common situation
      if elem['type']=="attrval":
        #print "tag->"+elem['tag']
        #print elem['name']
        i0=data.find(code)
        #i1=data[:i0].rfind("=")
        try:
          i1=data[:i0].rfind(elem['name'])
        # stupid unicode errors, must check later
        except UnicodeDecodeError:
          continue

        start=data[i1:i0].replace(" ","")[len(elem['name']):]
        print "start="+start
        if start.startswith("='"): payload="'"
        if start.startswith('="'): payload='"'
        if elem['tag'].lower()=="img":
          payload+="/>"
        else:
          payload+="></"+elem['tag']+">"
        for xss in self.independant_payloads:
          params[var]=payload+xss.replace("__XSS__",code)
          if referer!="": #POST
            if self.verbose==2:
              print "+ "+page
              print "  ",params
            dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
          else:#GET
            url=page+"?"+self.HTTP.uqe(params)
            dat=self.HTTP.send(url).getPage()

          if self.validXSS(dat,code):
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(params),
                              "XSS ("+var+")")
            if referer!="":
              print "Found XSS in",page
              print "  with params =",self.HTTP.encode(params)
              print "  coming from",referer

            else:
              if self.color==0:
                print "XSS ("+var+") in",page
                print "\tEvil url:",url
              else:
                print "XSS",":",url.replace(var+"=","\033[0;31m"+var+"\033[0;0m=")
            return True

      # this should not happen but you never know...
      elif elem['type']=="attrname": # name,tag
        #print "attrname"
        if code==elem['name']:
          for xss in self.independant_payloads:
            params[var]='>'+xss.replace("__XSS__",code)

            if referer!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.uqe(params),
                                "XSS ("+var+")")
              if referer!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",referer

              else:
                if self.color==0:
                  print "XSS ("+var+") in",page
                  print "\tEvil url:",url
                else:
                  print "XSS",":",url.replace(var+"=","\033[0;31m"+var+"\033[0;0m=")
              return True

      elif elem['type']=="tag":
        if elem['value'].startswith(code):
          # use independant payloads, just remove the first character (<)
          for xss in self.independant_payloads:
            params[var]=xss.replace("__XSS__",code)[1:]

            if referer!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.uqe(params),
                                "XSS ("+var+")")
              if referer!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",referer

              else:
                if self.color==0:
                  print "XSS ("+var+") in",page
                  print "\tEvil url:",url
                else:
                  print "XSS",":",url.replace(var+"=","\033[0;31m"+var+"\033[0;0m=")
              return True
        else:
          for xss in self.independant_payloads:
            #close tag and inject independant payloads
            params[var]="/>"+xss.replace("__XSS__",code)

            if referer!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.uqe(params),
                                "XSS ("+var+")")
              if referer!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",referer

              else:
                if self.color==0:
                  print "XSS ("+var+") in",page
                  print "\tEvil url:",url
                else:
                  print "XSS",":",url.replace(var+"=","\033[0;31m"+var+"\033[0;0m=")
              return True

      # another common one
      elif elem['type']=="text":
        payload=""
        if elem['parent']=="title": # Oops we are in the head
          payload="</title>"

        for xss in self.independant_payloads:
          params[var]=payload+xss.replace("__XSS__",code)

          if referer!="": #POST
            if self.verbose==2:
              print "+ "+page
              print "  ",params
            dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
          else:
            url=page+"?"+self.HTTP.uqe(params)
            dat=self.HTTP.send(url).getPage()

          if self.validXSS(dat,code):
            self.reportGen.logVulnerability(Vulnerability.XSS,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.uqe(params),
                              "XSS ("+var+")")
            if referer!="":
              print "Found XSS in",page
              print "  with params =",self.HTTP.encode(params)
              print "  coming from",referer

            else:
              if self.color==0:
                print "XSS ("+var+") in",page
                print "\tEvil url:",url
              else:
                print "XSS",":",url.replace(var+"=","\033[0;31m"+var+"\033[0;0m=")
            return True

      #data=data.partition(code)[2] #reduire la zone de recherche
      data=data.replace(code,"none",1)#reduire la zone de recherche
    return False

