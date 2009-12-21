import os
from xml.parsers import expat
from xml.dom.minidom import Document

class CrawlerPersister:
  """
  This class makes the persistence tasks for persisting the crawler parameters
  in other to can continue the process in the future.
  """

  CRAWLER_DATA_DIR_NAME = "scans"
  BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__),'../..'))
  CRAWLER_DATA_DIR = BASE_DIR+"/"+CRAWLER_DATA_DIR_NAME

  ROOT_URL = "rootURL"
  TO_BROWSE = "toBrowse"
  BROWSED   = "browsed"
  URL = "url"
  URL_DATA = "url_data"
  FORMS    = "forms"
  FORM     = "form"
  FORM_URL = "url"
  FORM_TO  = "to"
  INPUTS = "inputs"
  INPUT  = "input"
  INPUT_NAME  = "name"
  INPUT_VALUE = "value"
  UPLOADS = "uploads"
  URI = "uri"
  HEADER = "header"
  HEADER_NAME = "name"
  HEADER_VALUE = "value"
  ENCODING = "encoding"

  toBrowse = []
  browsed  = {}
  urls     = []
  inputs   = {}
  form     = []
  forms    = []
  uploads  = []
  headers  = {}
  rootURL = ""

  tag = ""
  array = None

  url   = ""


  def __init__(self):
    self.form = [0, 1, 2, 3]

  def isDataForUrl(self,fileName):
    return os.path.exists(fileName)

  def saveXML(self, fileName):
    """
    Exports the crawler parameters to an XML file.
    @param fileName The file where is loaded the crawler data
    """
    xml = Document()
    root = xml.createElement("root")
    xml.appendChild(root)

    rootUrlEl = xml.createElement(self.ROOT_URL)
    rootUrlEl.appendChild(xml.createTextNode(self.rootURL.encode("UTF-8")))
    root.appendChild(rootUrlEl)

    toBrowseEl = xml.createElement(self.TO_BROWSE)
    for url in self.toBrowse:
      urlEl = xml.createElement(self.URL)
      urlEl.appendChild(xml.createTextNode(url.encode("UTF-8")))
      toBrowseEl.appendChild(urlEl)
    root.appendChild(toBrowseEl)

    browsedEl = xml.createElement(self.BROWSED)
    for url, headers in self.browsed.items():
      urlEl = xml.createElement(self.URL_DATA)
      urlEl.setAttribute(self.URI, url.encode("UTF-8"))
      for k, v in headers.items():
        headEl = xml.createElement(self.HEADER)
        headEl.setAttribute(self.HEADER_NAME, k.encode("UTF-8"))
        headEl.setAttribute(self.HEADER_VALUE, v.encode("UTF-8"))
        urlEl.appendChild(headEl)
      browsedEl.appendChild(urlEl)
    root.appendChild(browsedEl)

    formsEl = xml.createElement(self.FORMS)
    for form in self.forms:
      formEl = xml.createElement(self.FORM)
      formEl.setAttribute(self.FORM_URL, form[0].encode("UTF-8"))
      formEl.setAttribute(self.FORM_TO, form[2].encode("UTF-8"))
      if form[3] != None:
        formEl.setAttribute(self.ENCODING, form[3].encode("UTF-8"))

      inputsEl = xml.createElement(self.INPUTS)
      for k, v in form[1].items():
        inputEl = xml.createElement(self.INPUT)
        inputEl.setAttribute(self.INPUT_NAME, k.encode("UTF-8"))
        inputEl.setAttribute(self.INPUT_VALUE, v.encode("UTF-8"))
        inputsEl.appendChild(inputEl)
      formEl.appendChild(inputsEl)
      formsEl.appendChild(formEl)
    root.appendChild(formsEl)

    uploadsEl = xml.createElement(self.UPLOADS)
    for url in self.uploads:
      urlEl = xml.createElement(self.URL)
      urlEl.appendChild(xml.createTextNode(url.encode("UTF-8")))
      uploadsEl.appendChild(urlEl)
    root.appendChild(uploadsEl)

    f = open(fileName,"w")
    try:
        xml.writexml(f, "    ", "    ", "\n", "UTF-8")
    finally:
        f.close()


  def loadXML(self, fileName):
    """
    Loads the crawler parameters from an XML file.
    @param fileName The file from where is loaded the crawler data
    """
    self._parser = expat.ParserCreate()
    self._parser.StartElementHandler  = self.__start_element
    self._parser.EndElementHandler    = self.__end_element
    self._parser.CharacterDataHandler = self.__char_data

    f = None
    try:
      f = open(fileName)
      content = f.read()
      self.__feed(content.replace("\n",""))
    finally:
      if f != None:
        f.close()

  
  def __feed(self, data):
    self._parser.Parse(data, 0)


  def __close(self):
    self._parser.Parse("", 1)
    del self._parser


  def __start_element(self, name, attrs):
    if name == self.TO_BROWSE:
      self.array = self.toBrowse
    elif name == self.BROWSED:
      self.array = self.browsed
    elif name == self.UPLOADS:
      self.array = self.uploads
    elif name == self.URL_DATA:
      self.url = attrs[self.URI]
      self.headers = {}
    elif name == self.URL:
      self.tag = self.URL
      self.url = ""
    elif name == self.HEADER:
      self.headers[attrs[self.HEADER_NAME]] = attrs[self.HEADER_VALUE]
    elif name == self.ROOT_URL:
      self.tag = self.ROOT_URL
    elif name == self.INPUTS:
      self.inputs = {}
      self.array = self.inputs
    elif name == self.INPUT:
      self.inputs[attrs[self.INPUT_NAME]] = attrs[self.INPUT_VALUE]
    elif name == self.FORM:
      self.form[0] = attrs[self.FORM_URL]
      self.form[2] = attrs[self.FORM_TO]
      if attrs.has_key(self.ENCODING):
        self.form[3] = attrs[self.ENCODING]
      else:
        self.form[3] = None


  def __end_element(self, name):
    if name == self.URL_DATA:
      self.array[self.url] = self.headers
      headers = {}
    elif name == self.URL:
      self.array.append(self.url)
    elif name == self.FORM:
      self.form[1] = self.inputs
      self.forms.append(self.form)
      self.form = [0, 1, 2, 3]


  def __char_data(self, data):
    if self.tag == self.ROOT_URL:
      self.rootURL = data.strip(" ");
    elif self.tag == self.URL:
      self.url = data.strip(" ")
    self.tag = ""

  
  def setRootURL(self, rootURL):
    self.rootURL = rootURL

  def getRootURL(self):
    return self.rootURL

  
  def setToBrose(self, toBrowse):
    self.toBrowse = toBrowse

  def getToBrose(self):
    return self.toBrowse


  def setBrowsed(self, browsed):
    self.browsed = browsed

  def getBrowsed(self):
    return self.browsed


  def setForms(self, forms):
    self.forms = forms

  def getForms(self):
    return self.forms


  def setUploads(self, uploads):
    self.uploads = uploads

  def getUploads(self):
    return self.uploads


