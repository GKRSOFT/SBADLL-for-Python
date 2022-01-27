#!/usr/bin/python

# -*- coding: utf-8 -*-

"""Copyright (c) 2022 GKRSOFT

All rights reserved.

For detailed copyright information see the README file.
GNU General Public License v3.0 
"""

 

__LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

__author__ = 'GKRSOFT'

__version__ = '2022.0.1'

__contact__ = ''

 

def __emain(msg):

    def encryptMessage(key, message):

        return translateMessage(key, message, 'encrypt')

 

    def decryptMessage(key, message):

        return translateMessage(key, message, 'decrypt')

 

    def translateMessage(key, message, mode):

        translated = []

        keyIndex = 0

        key = key.upper()

        for symbol in message:

            num = __LETTERS.find(symbol.upper())

            if num != -1:

                if mode == 'encrypt':

                    num += __LETTERS.find(key[keyIndex])

                elif mode == 'decrypt':

                    num -= __LETTERS.find(key[keyIndex])

 

                num %= len(__LETTERS)

                if symbol.isupper():

                    translated.append(__LETTERS[num])

                elif symbol.islower():

                     translated.append(__LETTERS[num].lower())

                keyIndex += 1

                if keyIndex == len(key):

                    keyIndex = 0

            else:

                translated.append(symbol)

        return ''.join(translated)

       

    myMessage =msg

    myKey = 'your key here'

    myMode = 'encrypt'

 

    if myMode == 'decrypt':

        translated = encryptMessage(myKey, myMessage)

    elif myMode == 'decrypt':

         translated = decryptMessage(myKey, myMessage)

    return translated      

 

__mn = __emain("libraries")

__mn1 = str(__mn).replace("'","").replace("[","").replace("]","").replace(" ","")

__mn =list(__mn1.split(','))

__m = map(__import__, __mn)

__PY3 = __m[0].version_info > (3,)

if __PY3:

    long = int

 

def __majic(mushroom):

    magicNumbers = []

    fname = ('d')

    with open(fname, 'rb') as in_file:

        magic = __m[9].load(in_file)

 

    def strToNum(n):

      val = 0

      col = long(1)

      if n[:1] == 'x': n = '0' + n

      if n[:2] == '0x':

        n = __m[5].lower(n[2:])

        while len(n) > 0:

          l = n[len(n) - 1]

          val = val + __m[5].hexdigits.index(l) * col

          col = col * 16

          n = n[:len(n)-1]

      elif n[0] == '\\':

        n = n[1:]

        while len(n) > 0:

          l = n[len(n) - 1]

          if ord(l) < 48 or ord(l) > 57: break

          val = val + int(l) * col

          col = col * 8

          n = n[:len(n)-1]

      else:

        val = __m[5].atol(n)

      return val

          

    def unescape(s):

      while 1:

        m = __m[2].search(r'\\', s)

        if not m: break

        x = m.start()+1

        if m.end() == len(s):

          s = s[:len(s)-1] + ' '

        elif s[x:x+2] == '0x':

          c = chr(strToNum(s[x:x+4]))

          s = s[:x-1] + c + s[x+4:]

        elif s[m.start()+1] == 'x':

          c = chr(strToNum(s[x:x+3]))

          s = s[:x-1] + c + s[x+3:]

        elif ord(s[x]) > 47 and ord(s[x]) < 58:

          end = x

          while (ord(s[end]) > 47 and ord(s[end]) < 58):

            end = end + 1

            if end > len(s) - 1: break

          c = chr(strToNum(s[x-1:end]))

          s = s[:x-1] + c + s[end:]

        elif s[x] == 'n':

          s = s[:x-1] + '\n' + s[x+1:]

        else:

          break

      return s

 

    class magicTest:

      def __init__(self, offset, t, op, value, msg, mask = None):

        if t.count('&') > 0:

          mask = strToNum(t[t.index('&')+1:]) 

          t = t[:t.index('&')]

        if type(offset) == type('a'):

          self.offset = strToNum(offset)

        else:

          self.offset = offset

        self.type = t

        self.msg = msg

        self.subTests = []

        self.op = op

        self.mask = mask

        self.value = value

         

 

      def test(self, data):

        if self.mask:

          data = data & self.mask

        if self.op == '=':

          if self.value == data: return self.msg

        elif self.op ==  '<':

          pass

        elif self.op ==  '>':

          pass

        elif self.op ==  '&':

          pass

        elif self.op ==  '^':

          pass

        return None

 

      def compare(self, data):

        try:

          if self.type == 'string':

            c = ''; s = ''

            for i in range(0, len(self.value)+1):

              if i + self.offset > len(data) - 1: break

              s = s + c

              [c] = __m[7].unpack('c', data[self.offset + i])

            data = s

          elif self.type == 'short':

            [data] = __m[7].unpack('h', data[self.offset : self.offset + 2])

          elif self.type == 'leshort':

            [data] = __m[7].unpack('<h', data[self.offset : self.offset + 2])

          elif self.type == 'beshort':

            [data] = __m[7].unpack('>H', data[self.offset : self.offset + 2])

          elif self.type == 'long':

            [data] = __m[7].unpack('l', data[self.offset : self.offset + 4])

          elif self.type == 'lelong':

            [data] = __m[7].unpack('<l', data[self.offset : self.offset + 4])

          elif self.type == 'belong':

            [data] = __m[7].unpack('>l', data[self.offset : self.offset + 4])

          else:

            #print

            pass

        except:

          return None

     

        return self.test(data)

       

    def load(file):

      global magicNumbers

      lines = open(file).readlines()

      last = { 0: None }

      for line in lines:

        if __m[2].match(r'\s*#', line):

          continue

        else:

          line = __m[5].rstrip(line)

          line = __m[2].split(r'\s*', line)

          if len(line) < 3:

            continue

          offset = line[0]

          type = line[1]

          value = line[2]

          level = 0

          while offset[0] == '>':

            level = level + 1

            offset = offset[1:]

          l = magicNumbers

          if level > 0:

            l = last[level - 1].subTests

          if offset[0] == '(':

            print 'SKIPPING ' + __m[5].join(list(line[3:]))

            pass

          elif offset[0] == '&':

            print 'SKIPPING ' + __m[5].join(list(line[3:]))

            pass

          else:

            operands = ['=', '<', '>', '&']

            if operands.count(value[0]) > 0:

              op = value[0]

              value = value[1:]

            else:

              print str([value, operands])

              if len(value) >1 and value[0] == '\\' and operands.count(value[1]) >0:

                value = value[1:]

              op = '='

 

            mask = None

            if type == 'string':

              while 1:

                value = unescape(value)

                if value[len(value)-1] == ' ' and len(line) > 3:

                  value = value + line[3]

                  del line[3]

                else:

                  break

            else:

              if value.count('&') != 0:

                mask = value[(value.index('&') + 1):]

                value = value[:(value.index('&')+1)]

              try: value = strToNum(value)

              except: continue

            msg = __m[5].join(list(line[3:]))

            new = magicTest(offset, type, op, value, msg, mask)

            last[level] = new

            l.append(new)

 

    def whatis(data):

      for test in magicNumbers:

         m = test.compare(data)

         if m: return m

      for c in data:

        if ord(c) > 128:

          return 'data'

      if __m[5].find('The', data, 0, 8192) > -1:

        return 'English text'

      if __m[5].find('def', data, 0, 8192) > -1:

        return 'Python Source'

      return 'ASCII text'

             

    def mfile(file):

      try:

        return whatis(open(file, 'r').read(8192))

      except Exception, e:

        if str(e) == '[Errno 21] Is a directory':

          return 'directory'

        else:

          raise e

 

    for mag in magic:

      magicNumbers.append(magicTest(mag[0], mag[1], mag[2], mag[3], mag[4]))

 

    return mfile(mushroom)         

def __extract_infos(fpath):

    def get_entropy(data):

        if len(data) == 0:

            return 0.0

        occurences = __m[6].array('L', [0]*256)

        for x in data:

            occurences[x if isinstance(x, int) else ord(x)] += 1

 

        entropy = 0

        for x in occurences:

            if x:

                p_x = float(x) / len(data)

                entropy -= p_x*__m[4].log(p_x, 2)

 

        return entropy

 

    def __get_resources(pe):

        """Extract resources :

        [entropy, size]"""

        resources = []

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):

            try:

                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:

                    if hasattr(resource_type, 'directory'):

                        for resource_id in resource_type.directory.entries:

                            if hasattr(resource_id, 'directory'):

                                for resource_lang in resource_id.directory.entries:

                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)

                                    size = resource_lang.data.struct.Size

                                    entropy = get_entropy(data)

 

                                    resources.append([entropy, size])

            except Exception as e:

                return resources

        return resources

 

    def __get_version_info(pe):

        """Return version infos"""

        res = {}

        for fileinfo in pe.FileInfo:

            if fileinfo.Key == 'StringFileInfo':

                for st in fileinfo.StringTable:

                    for entry in st.entries.items():

                        res[entry[0]] = entry[1]

            if fileinfo.Key == 'VarFileInfo':

                for var in fileinfo.Var:

                    res[var.entry.items()[0][0]] = var.entry.items()[0][1]

        if hasattr(pe, 'VS_FIXEDFILEINFO'):

              res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags

              res['os'] = pe.VS_FIXEDFILEINFO.FileOS

              res['type'] = pe.VS_FIXEDFILEINFO.FileType

              res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS

              res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS

              res['signature'] = pe.VS_FIXEDFILEINFO.Signature

              res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion

        return res

 

    try:

        res = {}

        pe = __m[11].PE(fpath)

        res['Machine'] = pe.FILE_HEADER.Machine

        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader

        res['Characteristics'] = pe.FILE_HEADER.Characteristics

        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion

        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion

        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode

        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData

        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData

        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode

        try:

            res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData

        except AttributeError:

            res['BaseOfData'] = 0

        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase

        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment

        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment

        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion

        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion

        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion

        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion

        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion

        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage

        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders

        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum

        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem

        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics

        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve

        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit

        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve

        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit

        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags

        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

 

        # Sections

        res['SectionsNb'] = len(pe.sections)

        entropy = map(lambda x:x.get_entropy(), pe.sections)

        res['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))

        res['SectionsMinEntropy'] = min(entropy)

        res['SectionsMaxEntropy'] = max(entropy)

        raw_sizes = map(lambda x:x.SizeOfRawData, pe.sections)

        res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))

        res['SectionsMinRawsize'] = min(raw_sizes)

        res['SectionsMaxRawsize'] = max(raw_sizes)

        virtual_sizes = map(lambda x:x.Misc_VirtualSize, pe.sections)

        res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))

        res['SectionsMinVirtualsize'] = min(virtual_sizes)

        res['SectionMaxVirtualsize'] = max(virtual_sizes)

 

        #Imports

        try:

            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)

            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])

            res['ImportsNb'] = len(imports)

            res['ImportsNbOrdinal'] = len(filter(lambda x:x.name is None, imports))

        except AttributeError:

            res['ImportsNbDLL'] = 0

            res['ImportsNb'] = 0

            res['ImportsNbOrdinal'] = 0

 

        #Exports

        try:

            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        except AttributeError:

            # No export

            res['ExportNb'] = 0

        #Resources

        resources= __get_resources(pe)

        res['ResourcesNb'] = len(resources)

        if len(resources)> 0:

            entropy = map(lambda x:x[0], resources)

            res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))

            res['ResourcesMinEntropy'] = min(entropy)

            res['ResourcesMaxEntropy'] = max(entropy)

            sizes = map(lambda x:x[1], resources)

            res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))

            res['ResourcesMinSize'] = min(sizes)

            res['ResourcesMaxSize'] = max(sizes)

        else:

            res['ResourcesNb'] = 0

            res['ResourcesMeanEntropy'] = 0

            res['ResourcesMinEntropy'] = 0

            res['ResourcesMaxEntropy'] = 0

            res['ResourcesMeanSize'] = 0

            res['ResourcesMinSize'] = 0

            res['ResourcesMaxSize'] = 0

 

        # Load configuration size

        try:

            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size

        except AttributeError:

            res['LoadConfigurationSize'] = 0

 

 

        # Version configuration size

        try:

            version_infos = __get_version_info(pe)

            res['VersionInformationSize'] = len(version_infos.keys())

        except AttributeError:

            res['VersionInformationSize'] = 0

        return res

    except Exception, e:

        print e

        pass

def __pmain(file_path):

    try:   

        def find_entry_point_section(pe, eop_rva):

            for section in pe.sections:

                if section.contains_rva(eop_rva):

                    return section

            return      

        

        def search(sig):

            try:

                i = 0

                a = open("f", 'r')

                sig1 = sig.split(" ")

                while(True):

                    l=a.readline()

                    if i > 1:

                        n=a.readline().strip()

                        s=a.readline()

                        e=a.readline()

                        sig2 = s.split(" = ")[1].split(" ")

                        j = 0

                        isig2 = len(sig2)-1

                        for s2 in sig2:

                            if(sig1[j] == s2)or(s2 == "??"):

                                j = j+1

                                if j == isig2:

                                    print("Warning file exactly matched 100%% of %s" % n )

                                    return

                                if (j/isig2 > 0.7):

                                    print("Warning file closely matches %d%% of %s" % ( int((j/isig2)*100), n) )

                                    break

                            else:

                                break

                    i = i + 1

 

           except:

                print("No matches found.")

                pass

            return

 

        def getSignature(file_path):

            try:

                pe = __m[11].PE(file_path, fast_load=True)

                eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint

                code_section = find_entry_point_section(pe, eop)

                if not code_section:

                    return

                code_at_oep = code_section.get_data(eop, 100)

                x = True

                for c in code_at_oep:

                    if x:

                        s = ( "%s" % "{:02x}".format(ord(c))).upper()

                        x = False

                    else:

                        s = s + " " + ( "%s" % "{:02x}".format(ord(c))).upper()

                return s

 

            except __m[11].PEFormatError as pe_err:

                if pe_err:

                    pe_err = ""

                print("[-] error while parsing file {}:\n\t{}".format(file_path,

                                                                      pe_err))

 

        s = getSignature(file_path)

        search(s)

       

    except Exception, e:

        print (e)

def __HashSub(hash1, filename, upper, seek, size):

    def binary_search2(fIn, target, upper, seek, size):

        target = target.upper()

 

        lower = long(0)

        upper = int(upper)

        seek = int(seek)

        size = int(size)

       

        val = ""

        while lower < upper:

            x = lower + (upper - lower) // 2

            fIn.seek(x*seek)

            val = str(fIn.read(size)).upper()

     

            if target == val:

                return 1

            elif target > val:

                if lower == x:

                    break

                lower = x

            elif target < val:

                if upper == x:

                    break

                upper = x

        return 0

       

    dHashes = {}

    dProducts = {}

    header = None

    fIn = open(filename, 'rb')

    return binary_search2(fIn, hash1, upper, seek, size)

def __md5(fname):

    hash_md5 = __m[10].md5()

    with open(fname, "rb") as f:

        for chunk in iter(lambda: f.read(4096), b""):

            hash_md5.update(chunk)

    return hash_md5.hexdigest()

def __Entropy(text):

    log2=lambda x:__m[4].log(x)/__m[4].log(2)

    exr={}

    infoc=0

    for each in text:

        try:

            exr[each]+=1

        except:

            exr[each]=1

    textlen=len(text)

    for k,v in exr.items():

        freq  =  1.0*v/textlen

        infoc+=freq*log2(freq)

    infoc*=-1

    return infoc

def __corpus():

    """

    """

    pass   

def __main(args):

    # MD5

    WL = 0

    BL = 0

    CL = 0

    res = 2

    try:

        if (args.checkHashes==False):  

            MD5 = __md5(args.FILE)

 

        # Whitelist

        try:

            WL = 0

            WL_MaxCount = 0

            WL_Record = 0

            WL_Hash = 0

            WL_File = "a"

            WL = __HashSub(MD5, WL_File, WL_MaxCount, WL_Record, WL_Hash)

        except:

            pass

       

        # Blacklist

        try:

            BL = 0

            BL_MaxCount = 0

            BL_Record = 0

            BL_Hash = 0

            BL_File = "b"

            BL = __HashSub(MD5, BL_File, BL_MaxCount, BL_Record, BL_Hash)

        except:

            pass

 

        # Antivirus

        try:

            CL = 0

            CL_MaxCount = 0

            CL_Record = 0

            CL_Hash = 0

            CL_File = "c"

            CL = __HashSub(MD5, CL_File, CL_MaxCount, CL_Record, CL_Hash)

        except:

            pass

        if (WL + BL + CL) > 0:

            res = 3       

    except:

        pass

 

    # peid

    try:

        if (args.packer==True):

            D = 0

            D = __pmain(args.FILE)

    except:

        pass

 

 

    # Entropy

    try:

        if (args.entropy==True):

            E = 0

            E = __Entropy(args.FILE)

            print("Entropy = %s" % E)

    except:

        pass

 

 

    # Magic

    try:

        if (args.filetype==True):

            F = 0

            F = __majic(args.FILE)

            print("File type = %s" % F)

    except:

        pass

 

 

    # ML

    if res == 2:

        fname = ""

        try:

            print(__m[1].getcwd())

            fname = ('model')

            with open(fname,'rb')as in_file:

                clf=__m[9].load(in_file)

 

            fname2 = ('features')

            with open(fname2,'rb')as in_file:

                features =__m[9].load(in_file)

 

            data = __extract_infos(args.FILE)

            print data

           

            pe_features = map(lambda x:data[x], features)

            print pe_features

           

            res= clf.predict([pe_features])[0]

            print res

           

        except Exception, e:

            print ("ML %s" % e)

            res = 2

            pass

    mesg =""

    if WL == 1:

        mesg = "is on the Whitelist"

    if BL == 1:

        mesg = "is on the Blacklist"

    if CL == 1:

        mesg = "is on the Antivirus list"

    if WL+BL+CL>0:

        print('%s %s' % (__m[1].path.basename(__m[0].argv[1]),mesg))

        res = 3

       

    if res == 2:

        mesg = " - Warning missing or unable to read %s" % fname

    elif res == 0:

        mesg =  "bad"

    elif res == 1:

        mesg = "good"

    if res < 2:

        print('%s %s' % (__m[1].path.basename(__m[0].argv[1]),mesg))                       

if __name__ == '__main__':

    try:

        parser = __m[8].ArgumentParser(description='Static Binary Analysis of files')

        parser.add_argument('FILE', help='File to be tested')

        parser.add_argument('-p', action='store_true', default=False,

                        dest='packer', help='Check for packer')

        parser.add_argument('-e', action='store_true', default=False,

                        dest='entropy', help='Check for entropy')

        parser.add_argument('-f', action='store_true', default=False,

                        dest='filetype', help='Check file type')

        parser.add_argument('-c', action='store_true', default=False,

                        dest='checkHashes', help='Turn Hash checks off')

        parser.add_argument('-v', action='version', version='%(prog)s 1.0')

        args = parser.parse_args()

        __main(args)

    except Exception, e:

            print ("%s" % e)

            pass          
