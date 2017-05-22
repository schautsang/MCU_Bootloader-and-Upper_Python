
#filename: bin.py

from array import array
from binascii import hexlify, unhexlify
from bisect import bisect_right
import getopt
import os
import sys

# Updates a running CRC with the provided byte
POLY = 0x1021       # CRC16-CCITT (X^16+X^12+X^5+1)


if sys.version_info[0] >= 3:
    # Python 3
    Python = 3

    def asbytes(s):
        if isinstance(s, bytes):
            return s
        return s.encode('latin1')
    def asstr(s):
        if isinstance(s, str):
            return s
        return s.decode('latin1')

    IntTypes = (int,)
    StrType = str
    UnicodeType = str

    range_g = range     # range generator
    def range_l(*args): # range list
        return list(range(*args))

    def dict_keys(dikt):        # dict keys list
        return list(dikt.keys())
    def dict_keys_g(dikt):      # dict keys generator
        return dikt.keys()
    def dict_items_g(dikt):     # dict items generator
        return dikt.items()

    from io import StringIO, BytesIO

    def get_binary_stdout():
        return sys.stdout.buffer

    def get_binary_stdin():
        return sys.stdin.buffer

else:
    # Python 2
    Python = 2

    asbytes = str
    asstr = str

    IntTypes = (int, long)
    StrType = basestring
    UnicodeType = unicode

    #range_g = xrange    # range generator
    def range_g(*args):
        # we want to use xrange here but on python 2 it does not work with long ints
        try:
            return xrange(*args)
        except OverflowError:
            start = 0
            stop = 0
            step = 1
            n = len(args)
            if n == 1:
                stop = args[0]
            elif n == 2:
                start, stop = args
            elif n == 3:
                start, stop, step = args
            else:
                raise TypeError('wrong number of arguments in range_g call!')
            if step == 0:
                raise ValueError('step cannot be zero')
            if step > 0:
                def up(start, stop, step):
                    while start < stop:
                        yield start
                        start += step
                return up(start, stop, step)
            else:
                def down(start, stop, step):
                    while start > stop:
                        yield start
                        start += step
                return down(start, stop, step)

    range_l = range     # range list

    def dict_keys(dikt):        # dict keys list
        return dikt.keys()
    def dict_keys_g(dikt):      # dict keys generator
        return dikt.keys()
    def dict_items_g(dikt):     # dict items generator
        return dikt.items()

    from cStringIO import StringIO
    BytesIO = StringIO

    def _force_stream_binary(stream):
        """Force binary mode for stream on Windows."""
        if os.name == 'nt':
            f_fileno = getattr(stream, 'fileno', None)
            if f_fileno:
                fileno = f_fileno()
                if fileno >= 0:
                    import msvcrt
                    msvcrt.setmode(fileno, os.O_BINARY)
        return stream

    def get_binary_stdout():
        return _force_stream_binary(sys.stdout)

    def get_binary_stdin():
        return _force_stream_binary(sys.stdin)


##
# IntelHex Errors Hierarchy:
#
#  IntelHexError    - basic error
#       HexReaderError  - general hex reader error
#           AddressOverlapError - data for the same address overlap
#           HexRecordError      - hex record decoder base error
#               RecordLengthError    - record has invalid length
#               RecordTypeError      - record has invalid type (RECTYP)
#               RecordChecksumError  - record checksum mismatch
#               EOFRecordError              - invalid EOF record (type 01)
#               ExtendedAddressRecordError  - extended address record base error
#                   ExtendedSegmentAddressRecordError   - invalid extended segment address record (type 02)
#                   ExtendedLinearAddressRecordError    - invalid extended linear address record (type 04)
#               StartAddressRecordError     - start address record base error
#                   StartSegmentAddressRecordError      - invalid start segment address record (type 03)
#                   StartLinearAddressRecordError       - invalid start linear address record (type 05)
#                   DuplicateStartAddressRecordError    - start address record appears twice
#                   InvalidStartAddressValueError       - invalid value of start addr record
#       _EndOfFile  - it's not real error, used internally by hex reader as signal that EOF record found
#       BadAccess16bit - not enough data to read 16 bit value (deprecated, see NotEnoughDataError)
#       NotEnoughDataError - not enough data to read N contiguous bytes
#       EmptyIntelHexError - requested operation cannot be performed with empty object

class IntelHexError(Exception):
    '''Base Exception class for IntelHex module'''

    _fmt = 'IntelHex base error'   #: format string

    def __init__(self, msg=None, **kw):
        """Initialize the Exception with the given message.
        """
        self.msg = msg
        for key, value in dict_items_g(kw):
            setattr(self, key, value)

    def __str__(self):
        """Return the message in this Exception."""
        if self.msg:
            return self.msg
        try:
            return self._fmt % self.__dict__
        except (NameError, ValueError, KeyError):
            e = sys.exc_info()[1]     # current exception
            return 'Unprintable exception %s: %s' \
                % (repr(e), str(e))

class _EndOfFile(IntelHexError):
    """Used for internal needs only."""
    _fmt = 'EOF record reached -- signal to stop read file'

class HexReaderError(IntelHexError):
    _fmt = 'Hex reader base error'

class AddressOverlapError(HexReaderError):
    _fmt = 'Hex file has data overlap at address 0x%(address)X on line %(line)d'

# class NotAHexFileError was removed in trunk.revno.54 because it's not used


class HexRecordError(HexReaderError):
    _fmt = 'Hex file contains invalid record at line %(line)d'


class RecordLengthError(HexRecordError):
    _fmt = 'Record at line %(line)d has invalid length'

class RecordTypeError(HexRecordError):
    _fmt = 'Record at line %(line)d has invalid record type'

class RecordChecksumError(HexRecordError):
    _fmt = 'Record at line %(line)d has invalid checksum'

class EOFRecordError(HexRecordError):
    _fmt = 'File has invalid End-of-File record'


class ExtendedAddressRecordError(HexRecordError):
    _fmt = 'Base class for extended address exceptions'

class ExtendedSegmentAddressRecordError(ExtendedAddressRecordError):
    _fmt = 'Invalid Extended Segment Address Record at line %(line)d'

class ExtendedLinearAddressRecordError(ExtendedAddressRecordError):
    _fmt = 'Invalid Extended Linear Address Record at line %(line)d'


class StartAddressRecordError(HexRecordError):
    _fmt = 'Base class for start address exceptions'

class StartSegmentAddressRecordError(StartAddressRecordError):
    _fmt = 'Invalid Start Segment Address Record at line %(line)d'

class StartLinearAddressRecordError(StartAddressRecordError):
    _fmt = 'Invalid Start Linear Address Record at line %(line)d'

class DuplicateStartAddressRecordError(StartAddressRecordError):
    _fmt = 'Start Address Record appears twice at line %(line)d'

class InvalidStartAddressValueError(StartAddressRecordError):
    _fmt = 'Invalid start address value: %(start_addr)s'


class NotEnoughDataError(IntelHexError):
    _fmt = ('Bad access at 0x%(address)X: '
            'not enough data to read %(length)d contiguous bytes')

class BadAccess16bit(NotEnoughDataError):
    _fmt = 'Bad access at 0x%(address)X: not enough data to read 16 bit value'

class EmptyIntelHexError(IntelHexError):
    _fmt = "Requested operation cannot be executed with empty object"


class _DeprecatedParam(object):
    pass

_DEPRECATED = _DeprecatedParam()


class intelhex(object):
    ''' Intel HEX file reader. '''

    def __init__(self, source=None):
        ''' Constructor. If source specified, object will be initialized
        with the contents of source. Otherwise the object will be empty.

        @param  source      source for initialization
                            (file name of HEX file, file object, addr dict or
                             other IntelHex object)
        '''
        # public members
        self.padding = 0x0FF
        # Start Address
        self.start_addr = None

        # private members
        self._buf = {}
        self._offset = 0

        # CRC16 init value
        self._crc = 0x0000


        if source is not None:
            if isinstance(source, StrType) or getattr(source, "read", None):
                # load hex file
                self.loadhex(source)
            elif isinstance(source, dict):
                self.fromdict(source)
            elif isinstance(source, intelhex):
                self.padding = source.padding
                if source.start_addr:
                    self.start_addr = source.start_addr.copy()
                self._buf = source._buf.copy()
            else:
                raise ValueError("source: bad initializer type")

    def _decode_record(self, s, line=0):
        '''Decode one record of HEX file.

        @param  s       line with HEX record.
        @param  line    line number (for error messages).

        @raise  EndOfFile   if EOF record encountered.
        '''
        s = s.rstrip('\r\n') # remove \r\n
        if not s:
            return          # empty line

        if s[0] == ':':
            try:
                bin = array('B', unhexlify(asbytes(s[1:]))) # make as UNSIGNED CHAR to store array
            except (TypeError, ValueError):
                # this might be raised by unhexlify when odd hexascii digits
                raise HexRecordError(line=line)
            length = len(bin)
            if length < 5:
                raise HexRecordError(line=line)
        else:
            raise HexRecordError(line=line)

        record_length = bin[0]
        if length != (5 + record_length): # 5 = 1 byte(record_length) + 2 byte(address) + 1 byte(record_type) + 1 byte(checksum)
            raise RecordLengthError(line=line)

        addr = bin[1]*256 + bin[2]

        record_type = bin[3]
        if not (0 <= record_type <= 5):
            raise RecordTypeError(line=line)

        crc = sum(bin)
        crc &= 0x0FF
        if crc != 0:
            raise RecordChecksumError(line=line)

        if record_type == 0:
            # data record
            addr += self._offset
            for i in range_g(4, 4+record_length):
                if not self._buf.get(addr, None) is None:
                    raise AddressOverlapError(address=addr, line=line)
                self._buf[addr] = bin[i]
                addr += 1   # FIXME: addr should be wrapped 
                            # BUT after 02 record (at 64K boundary)
                            # and after 04 record (at 4G boundary)

        elif record_type == 1:
            # end of file record
            if record_length != 0:
                raise EOFRecordError(line=line)
            raise _EndOfFile

        elif record_type == 2:
            # Extended 8086 Segment Record
            if record_length != 2 or addr != 0:
                raise ExtendedSegmentAddressRecordError(line=line)
            self._offset = (bin[4]*256 + bin[5]) * 16

        elif record_type == 4:
            # Extended Linear Address Record
            if record_length != 2 or addr != 0:
                raise ExtendedLinearAddressRecordError(line=line)
            self._offset = (bin[4]*256 + bin[5]) * 65536

        elif record_type == 3:
            # Start Segment Address Record
            if record_length != 4 or addr != 0:
                raise StartSegmentAddressRecordError(line=line)
            if self.start_addr:
                raise DuplicateStartAddressRecordError(line=line)
            self.start_addr = {'CS': bin[4]*256 + bin[5],
                               'IP': bin[6]*256 + bin[7],
                              }

        elif record_type == 5:
            # Start Linear Address Record
            if record_length != 4 or addr != 0:
                raise StartLinearAddressRecordError(line=line)
            if self.start_addr:
                raise DuplicateStartAddressRecordError(line=line)
            self.start_addr = {'EIP': (bin[4]*16777216 +
                                       bin[5]*65536 +
                                       bin[6]*256 +
                                       bin[7]),
                              }

    def loadhex(self, fobj):
        """Load hex file into internal buffer. This is not necessary
        if object was initialized with source set. This will overwrite
        addresses if object was already initialized.

        @param  fobj        file name or file-like object
        """
        if getattr(fobj, "read", None) is None:
            fobj = open(fobj, "r")
            fclose = fobj.close
        else:
            fclose = None

        self._offset = 0
        line = 0

        try:
            decode = self._decode_record
            try:
                for s in fobj:
                    line += 1
                    decode(s, line)
            except _EndOfFile:
                pass
        finally:
            if fclose:
                fclose()

    def loadbin(self, fobj, offset=0):
        """Load bin file into internal buffer. Not needed if source set in
        constructor. This will overwrite addresses without warning
        if object was already initialized.

        @param  fobj        file name or file-like object
        @param  offset      starting address offset
        """
        fread = getattr(fobj, "read", None)
        if fread is None:
            f = open(fobj, "rb")
            fread = f.read
            fclose = f.close
        else:
            fclose = None

        try:
            self.frombytes(array('B', asbytes(fread())), offset=offset)
        finally:
            if fclose:
                fclose()

    def loadfile(self, fobj, format):
        """Load data file into internal buffer. Preferred wrapper over
        loadbin or loadhex.

        @param  fobj        file name or file-like object
        @param  format      file format ("hex" or "bin")
        """
        if format == "hex":
            self.loadhex(fobj)
        elif format == "bin":
            self.loadbin(fobj)
        else:
            raise ValueError('format should be either "hex" or "bin";'
                ' got %r instead' % format)

    # alias (to be consistent with method tofile)
    fromfile = loadfile

    def fromdict(self, dikt):
        """Load data from dictionary. Dictionary should contain int keys
        representing addresses. Values should be the data to be stored in
        those addresses in unsigned char form (i.e. not strings).
        The dictionary may contain the key, ``start_addr``
        to indicate the starting address of the data as described in README.

        The contents of the dict will be merged with this object and will
        overwrite any conflicts. This function is not necessary if the
        object was initialized with source specified.
        """
        s = dikt.copy()
        start_addr = s.get('start_addr')
        if start_addr is not None:
            del s['start_addr']
        for k in dict_keys_g(s):
            if type(k) not in IntTypes or k < 0:
                raise ValueError('Source dictionary should have only int keys')
        self._buf.update(s)
        if start_addr is not None:
            self.start_addr = start_addr

    def frombytes(self, bytes, offset=0):
        """Load data from array or list of bytes.
        Similar to loadbin() method but works directly with iterable bytes.
        """
        for b in bytes:
            self._buf[offset] = b
            offset += 1

    def _get_start_end(self, start=None, end=None, size=None):
        """Return default values for start and end if they are None.
        If this IntelHex object is empty then it's error to
        invoke this method with both start and end as None. 
        """
        if (start,end) == (None,None) and self._buf == {}:
            raise EmptyIntelHexError
        if size is not None:
            if None not in (start, end):
                raise ValueError("tobinarray: you can't use start,end and size"
                                 " arguments in the same time")
            if (start, end) == (None, None):
                start = self.minaddr()
            if start is not None:
                end = start + size - 1
            else:
                start = end - size + 1
                if start < 0:
                    raise ValueError("tobinarray: invalid size (%d) "
                                     "for given end address (%d)" % (size,end))
        else:
            if start is None:
                start = self.minaddr()
            if end is None:
                end = self.maxaddr()
            if start > end:
                start, end = end, start
        return start, end

    def tobinarray(self, start=None, end=None, pad=_DEPRECATED, size=None):
        ''' Convert this object to binary form as array. If start and end 
        unspecified, they will be inferred from the data.
        @param  start   start address of output bytes.
        @param  end     end address of output bytes (inclusive).
        @param  pad     [DEPRECATED PARAMETER, please use self.padding instead]
                        fill empty spaces with this value
                        (if pad is None then this method uses self.padding).
        @param  size    size of the block, used with start or end parameter.
        @return         array of unsigned char data.
        '''
        if not isinstance(pad, _DeprecatedParam):
            print ("IntelHex.tobinarray: 'pad' parameter is deprecated.")
            if pad is not None:
                print ("Please, use IntelHex.padding attribute instead.")
            else:
                print ("Please, don't pass it explicitly.")
                print ("Use syntax like this: ih.tobinarray(start=xxx, end=yyy, size=zzz)")
        else:
            pad = None
        return self._tobinarray_really(start, end, pad, size)

    def update_crc16(self, byte):

        #Create the CRC "dividend"
        self._crc = self._crc ^ (byte << 8)
        # "Divide" the POLY into the dividend using CRC XOR subtraction for each
        # bit of the incoming data byte
        for i in range(8, 0, -1):
            # Save the MSB and shift the CRC value
            msb = self._crc >> 8
            self._crc = self._crc << 1
    
            # If MSB was 1, then the POLY can "divide" into the "dividend"
            if msb & 0x80:
            # XOR "subtract" the POLY
                self._crc ^= POLY

    def _tobinarray_really(self, start, end, pad, size):

        if pad is None:
            pad = self.padding

        bin = array('B')

        if self._buf == {} and None in (start, end):
            return bin

        if size is not None and size <= 0:
            raise ValueError("tobinarray: wrong value for size")

        start, end = self._get_start_end(start, end, size)

        bootf_index = 0
        i = start
        while i < end + 1:

            if end + 1 - i < 128:
                length = (1 + 4 + end + 1 - i)
            else:
                length = (1 + 4 + 128)

            addr = start + bootf_index

            bin.append(ord(b'$'))

            bin.append(length)

            if bootf_index == 0 or addr % 1024 == 0:
                command = ord(b'2')
            else:
                command = ord(b'3')
            bin.append(command)
            length = length - 1

            bin.append(addr >> 24 & 0x0FF)
            bin.append(addr >> 16 & 0x0FF)
            bin.append(addr >> 8 & 0x0FF)
            bin.append(addr & 0x0FF)
            length = length - 4

            bootf_index = bootf_index + length

            while length:
                bin.append(self._buf.get(i, pad))
                self.update_crc16(self._buf.get(i, pad))
                i = i + 1
                length = length - 1

        # make standard bin file
        #for i in range_g(start, end + 1):
            #bin.append(self._buf.get(i, pad))

        # make crc check frame
        bin.append(ord(b'$'))
        bin.append(ord(b'\x0B'))
        bin.append(ord(b'4'))
        bin.append(start >> 24 & 0x0FF)
        bin.append(start >> 16 & 0x0FF)
        bin.append(start >> 8 & 0x0FF)
        bin.append(start & 0x0FF)
        bin.append(end >> 24 & 0x0FF)
        bin.append(end >> 16 & 0x0FF)
        bin.append(end >> 8 & 0x0FF)
        bin.append(end & 0x0FF)
        bin.append(self._crc >> 8 & 0x0FF)
        bin.append(self._crc & 0x0FF)

        # make switch to app frame
        bin.append(ord(b'$'))
        bin.append(ord(b'\x01'))
        bin.append(ord(b'6'))


        return bin

    def tobinstr(self, start=None, end=None, pad=_DEPRECATED, size=None):
        ''' Convert to binary form and return as binary string.
        @param  start   start address of output bytes.
        @param  end     end address of output bytes (inclusive).
        @param  pad     [DEPRECATED PARAMETER, please use self.padding instead]
                        fill empty spaces with this value
                        (if pad is None then this method uses self.padding).
        @param  size    size of the block, used with start or end parameter.
        @return         string of binary data.
        '''
        if not isinstance(pad, _DeprecatedParam):
            print ("IntelHex.tobinstr: 'pad' parameter is deprecated.")
            if pad is not None:
                print ("Please, use IntelHex.padding attribute instead.")
            else:
                print ("Please, don't pass it explicitly.")
                print ("Use syntax like this: ih.tobinstr(start=xxx, end=yyy, size=zzz)")
        else:
            pad = None
        return self._tobinstr_really(start, end, pad, size)

    def _tobinstr_really(self, start, end, pad, size):
        return asbytes(self._tobinarray_really(start, end, pad, size).tostring())

    def tobinfile(self, fobj, start=None, end=None, pad=_DEPRECATED, size=None):
        '''Convert to binary and write to file.

        @param  fobj    file name or file object for writing output bytes.
        @param  start   start address of output bytes.
        @param  end     end address of output bytes (inclusive).
        @param  pad     [DEPRECATED PARAMETER, please use self.padding instead]
                        fill empty spaces with this value
                        (if pad is None then this method uses self.padding).
        @param  size    size of the block, used with start or end parameter.
        '''
        if not isinstance(pad, _DeprecatedParam):
            print ("IntelHex.tobinfile: 'pad' parameter is deprecated.")
            if pad is not None:
                print ("Please, use IntelHex.padding attribute instead.")
            else:
                print ("Please, don't pass it explicitly.")
                print ("Use syntax like this: ih.tobinfile(start=xxx, end=yyy, size=zzz)")
        else:
            pad = None
        if getattr(fobj, "write", None) is None:
            fobj = open(fobj, "wb")
            close_fd = True
        else:
            close_fd = False

        fobj.write(self._tobinstr_really(start, end, pad, size))

        if close_fd:
            fobj.close()

    def todict(self):
        '''Convert to python dictionary.

        @return         dict suitable for initializing another IntelHex object.
        '''
        r = {}
        r.update(self._buf)
        if self.start_addr:
            r['start_addr'] = self.start_addr
        return r

    def addresses(self):
        '''Returns all used addresses in sorted order.
        @return         list of occupied data addresses in sorted order. 
        '''
        aa = dict_keys(self._buf)
        aa.sort()
        return aa

    def minaddr(self):
        '''Get minimal address of HEX content.
        @return         minimal address or None if no data
        '''
        aa = dict_keys(self._buf)
        if aa == []:
            return None
        else:
            return min(aa)

    def maxaddr(self):
        '''Get maximal address of HEX content.
        @return         maximal address or None if no data
        '''
        aa = dict_keys(self._buf)
        if aa == []:
            return None
        else:
            return max(aa)

    def __getitem__(self, addr):
        ''' Get requested byte from address.
        @param  addr    address of byte.
        @return         byte if address exists in HEX file, or self.padding
                        if no data found.
        '''
        t = type(addr)
        if t in IntTypes:
            if addr < 0:
                raise TypeError('Address should be >= 0.')
            return self._buf.get(addr, self.padding)
        elif t == slice:
            addresses = dict_keys(self._buf)
            ih = IntelHex()
            if addresses:
                addresses.sort()
                start = addr.start or addresses[0]
                stop = addr.stop or (addresses[-1]+1)
                step = addr.step or 1
                for i in range_g(start, stop, step):
                    x = self._buf.get(i)
                    if x is not None:
                        ih[i] = x
            return ih
        else:
            raise TypeError('Address has unsupported type: %s' % t)

    def __setitem__(self, addr, byte):
        """Set byte at address."""
        t = type(addr)
        if t in IntTypes:
            if addr < 0:
                raise TypeError('Address should be >= 0.')
            self._buf[addr] = byte
        elif t == slice:
            if not isinstance(byte, (list, tuple)):
                raise ValueError('Slice operation expects sequence of bytes')
            start = addr.start
            stop = addr.stop
            step = addr.step or 1
            if None not in (start, stop):
                ra = range_l(start, stop, step)
                if len(ra) != len(byte):
                    raise ValueError('Length of bytes sequence does not match '
                        'address range')
            elif (start, stop) == (None, None):
                raise TypeError('Unsupported address range')
            elif start is None:
                start = stop - len(byte)
            elif stop is None:
                stop = start + len(byte)
            if start < 0:
                raise TypeError('start address cannot be negative')
            if stop < 0:
                raise TypeError('stop address cannot be negative')
            j = 0
            for i in range_g(start, stop, step):
                self._buf[i] = byte[j]
                j += 1
        else:
            raise TypeError('Address has unsupported type: %s' % t)

    def __delitem__(self, addr):
        """Delete byte at address."""
        t = type(addr)
        if t in IntTypes:
            if addr < 0:
                raise TypeError('Address should be >= 0.')
            del self._buf[addr]
        elif t == slice:
            addresses = dict_keys(self._buf)
            if addresses:
                addresses.sort()
                start = addr.start or addresses[0]
                stop = addr.stop or (addresses[-1]+1)
                step = addr.step or 1
                for i in range_g(start, stop, step):
                    x = self._buf.get(i)
                    if x is not None:
                        del self._buf[i]
        else:
            raise TypeError('Address has unsupported type: %s' % t)

    def __len__(self):
        """Return count of bytes with real values."""
        return len(dict_keys(self._buf))

    def write_hex_file(self, f, write_start_addr=True):
        """Write data to file f in HEX format.

        @param  f                   filename or file-like object for writing
        @param  write_start_addr    enable or disable writing start address
                                    record to file (enabled by default).
                                    If there is no start address in obj, nothing
                                    will be written regardless of this setting.
        """
        fwrite = getattr(f, "write", None)
        if fwrite:
            fobj = f
            fclose = None
        else:
            fobj = open(f, 'w')
            fwrite = fobj.write
            fclose = fobj.close

        # Translation table for uppercasing hex ascii string.
        # timeit shows that using hexstr.translate(table)
        # is faster than hexstr.upper():
        # 0.452ms vs. 0.652ms (translate vs. upper)
        if sys.version_info[0] >= 3:
            # Python 3
            table = bytes(range_l(256)).upper()
        else:
            # Python 2
            table = ''.join(chr(i).upper() for i in range_g(256))

        # start address record if any
        if self.start_addr and write_start_addr:
            keys = dict_keys(self.start_addr)
            keys.sort()
            bin = array('B', asbytes('\0'*9))
            if keys == ['CS','IP']:
                # Start Segment Address Record
                bin[0] = 4      # reclen
                bin[1] = 0      # offset msb
                bin[2] = 0      # offset lsb
                bin[3] = 3      # rectyp
                cs = self.start_addr['CS']
                bin[4] = (cs >> 8) & 0x0FF
                bin[5] = cs & 0x0FF
                ip = self.start_addr['IP']
                bin[6] = (ip >> 8) & 0x0FF
                bin[7] = ip & 0x0FF
                bin[8] = (-sum(bin)) & 0x0FF    # chksum
                fwrite(':' +
                       asstr(hexlify(bin.tostring()).translate(table)) +
                       '\n')
            elif keys == ['EIP']:
                # Start Linear Address Record
                bin[0] = 4      # reclen
                bin[1] = 0      # offset msb
                bin[2] = 0      # offset lsb
                bin[3] = 5      # rectyp
                eip = self.start_addr['EIP']
                bin[4] = (eip >> 24) & 0x0FF
                bin[5] = (eip >> 16) & 0x0FF
                bin[6] = (eip >> 8) & 0x0FF
                bin[7] = eip & 0x0FF
                bin[8] = (-sum(bin)) & 0x0FF    # chksum
                fwrite(':' +
                       asstr(hexlify(bin.tostring()).translate(table)) +
                       '\n')
            else:
                if fclose:
                    fclose()
                raise InvalidStartAddressValueError(start_addr=self.start_addr)

        # data
        addresses = dict_keys(self._buf)
        addresses.sort()
        addr_len = len(addresses)
        if addr_len:
            minaddr = addresses[0]
            maxaddr = addresses[-1]

            if maxaddr > 65535:
                need_offset_record = True
            else:
                need_offset_record = False
            high_ofs = 0

            cur_addr = minaddr
            cur_ix = 0

            while cur_addr <= maxaddr:
                if need_offset_record:
                    bin = array('B', asbytes('\0'*7))
                    bin[0] = 2      # reclen
                    bin[1] = 0      # offset msb
                    bin[2] = 0      # offset lsb
                    bin[3] = 4      # rectyp
                    high_ofs = int(cur_addr>>16)
                    b = divmod(high_ofs, 256)
                    bin[4] = b[0]   # msb of high_ofs
                    bin[5] = b[1]   # lsb of high_ofs
                    bin[6] = (-sum(bin)) & 0x0FF    # chksum
                    fwrite(':' +
                           asstr(hexlify(bin.tostring()).translate(table)) +
                           '\n')

                while True:
                    # produce one record
                    low_addr = cur_addr & 0x0FFFF
                    # chain_len off by 1
                    chain_len = min(15, 65535-low_addr, maxaddr-cur_addr)

                    # search continuous chain
                    stop_addr = cur_addr + chain_len
                    if chain_len:
                        ix = bisect_right(addresses, stop_addr,
                                          cur_ix,
                                          min(cur_ix+chain_len+1, addr_len))
                        chain_len = ix - cur_ix     # real chain_len
                        # there could be small holes in the chain
                        # but we will catch them by try-except later
                        # so for big continuous files we will work
                        # at maximum possible speed
                    else:
                        chain_len = 1               # real chain_len

                    bin = array('B', asbytes('\0'*(5+chain_len)))
                    b = divmod(low_addr, 256)
                    bin[1] = b[0]   # msb of low_addr
                    bin[2] = b[1]   # lsb of low_addr
                    bin[3] = 0          # rectype
                    try:    # if there is small holes we'll catch them
                        for i in range_g(chain_len):
                            bin[4+i] = self._buf[cur_addr+i]
                    except KeyError:
                        # we catch a hole so we should shrink the chain
                        chain_len = i
                        bin = bin[:5+i]
                    bin[0] = chain_len
                    bin[4+chain_len] = (-sum(bin)) & 0x0FF    # chksum
                    fwrite(':' +
                           asstr(hexlify(bin.tostring()).translate(table)) +
                           '\n')

                    # adjust cur_addr/cur_ix
                    cur_ix += chain_len
                    if cur_ix < addr_len:
                        cur_addr = addresses[cur_ix]
                    else:
                        cur_addr = maxaddr + 1
                        break
                    high_addr = int(cur_addr>>16)
                    if high_addr > high_ofs:
                        break

        # end-of-file record
        fwrite(":00000001FF\n")
        if fclose:
            fclose()

    def tofile(self, fobj, format):
        """Write data to hex or bin file. Preferred method over tobin or tohex.

        @param  fobj        file name or file-like object
        @param  format      file format ("hex" or "bin")
        """
        if format == 'hex':
            self.write_hex_file(fobj)
        elif format == 'bin':
            self.tobinfile(fobj)
        else:
            raise ValueError('format should be either "hex" or "bin";'
                ' got %r instead' % format)

    def gets(self, addr, length):
        """Get string of bytes from given address. If any entries are blank
        from addr through addr+length, a NotEnoughDataError exception will
        be raised. Padding is not used."""
        a = array('B', asbytes('\0'*length))
        try:
            for i in range_g(length):
                a[i] = self._buf[addr+i]
        except KeyError:
            raise NotEnoughDataError(address=addr, length=length)
        return asstr(a.tostring())

    def puts(self, addr, s):
        """Put string of bytes at given address. Will overwrite any previous
        entries.
        """
        a = array('B', asbytes(s))
        for i in range_g(len(a)):
            self._buf[addr+i] = a[i]

    def getsz(self, addr):
        """Get zero-terminated string from given address. Will raise 
        NotEnoughDataError exception if a hole is encountered before a 0.
        """
        i = 0
        try:
            while True:
                if self._buf[addr+i] == 0:
                    break
                i += 1
        except KeyError:
            raise NotEnoughDataError(msg=('Bad access at 0x%X: '
                'not enough data to read zero-terminated string') % addr)
        return self.gets(addr, i)

    def putsz(self, addr, s):
        """Put string in object at addr and append terminating zero at end."""
        self.puts(addr, s)
        self._buf[addr+len(s)] = 0

    def dump(self, tofile=None, width=16, withpadding=False):
        """Dump object content to specified file object or to stdout if None.
        Format is a hexdump with some header information at the beginning,
        addresses on the left, and data on right.

        @param  tofile          file-like object to dump to
        @param  width           number of bytes per line (i.e. columns)
        @param  withpadding     print padding character instead of '--'
        @raise  ValueError      if width is not a positive integer
        """

        if not isinstance(width,int) or width < 1:
            raise ValueError('width must be a positive integer.')
        # The integer can be of float type - does not work with bit operations
        width = int(width)
        if tofile is None:
            tofile = sys.stdout
            
        # start addr possibly
        if self.start_addr is not None:
            cs = self.start_addr.get('CS')
            ip = self.start_addr.get('IP')
            eip = self.start_addr.get('EIP')
            if eip is not None and cs is None and ip is None:
                tofile.write('EIP = 0x%08X\n' % eip)
            elif eip is None and cs is not None and ip is not None:
                tofile.write('CS = 0x%04X, IP = 0x%04X\n' % (cs, ip))
            else:
                tofile.write('start_addr = %r\n' % start_addr)
        # actual data
        addresses = dict_keys(self._buf)
        if addresses:
            addresses.sort()
            minaddr = addresses[0]
            maxaddr = addresses[-1]
            startaddr = (minaddr // width) * width
            endaddr = ((maxaddr // width) + 1) * width
            maxdigits = max(len(hex(endaddr)) - 2, 4)   # Less 2 to exclude '0x'
            templa = '%%0%dX' % maxdigits
            rangewidth = range_l(width)
            if withpadding:
                pad = self.padding
            else:
                pad = None
            for i in range_g(startaddr, endaddr, width):
                tofile.write(templa % i)
                tofile.write(' ')
                s = []
                for j in rangewidth:
                    x = self._buf.get(i+j, pad)
                    if x is not None:
                        tofile.write(' %02X' % x)
                        if 32 <= x < 127:   # GNU less does not like 0x7F (128 decimal) so we'd better show it as dot
                            s.append(chr(x))
                        else:
                            s.append('.')
                    else:
                        tofile.write(' --')
                        s.append(' ')
                tofile.write('  |' + ''.join(s) + '|\n')

    def merge(self, other, overlap='error'):
        """Merge content of other IntelHex object into current object (self).
        @param  other   other IntelHex object.
        @param  overlap action on overlap of data or starting addr:
                        - error: raising OverlapError;
                        - ignore: ignore other data and keep current data
                                  in overlapping region;
                        - replace: replace data with other data
                                  in overlapping region.

        @raise  TypeError       if other is not instance of IntelHex
        @raise  ValueError      if other is the same object as self 
                                (it can't merge itself)
        @raise  ValueError      if overlap argument has incorrect value
        @raise  AddressOverlapError    on overlapped data
        """
        # check args
        if not isinstance(other, IntelHex):
            raise TypeError('other should be IntelHex object')
        if other is self:
            raise ValueError("Can't merge itself")
        if overlap not in ('error', 'ignore', 'replace'):
            raise ValueError("overlap argument should be either "
                "'error', 'ignore' or 'replace'")
        # merge data
        this_buf = self._buf
        other_buf = other._buf
        for i in other_buf:
            if i in this_buf:
                if overlap == 'error':
                    raise AddressOverlapError(
                        'Data overlapped at address 0x%X' % i)
                elif overlap == 'ignore':
                    continue
            this_buf[i] = other_buf[i]
        # merge start_addr
        if self.start_addr != other.start_addr:
            if self.start_addr is None:     # set start addr from other
                self.start_addr = other.start_addr
            elif other.start_addr is None:  # keep existing start addr
                pass
            else:                           # conflict
                if overlap == 'error':
                    raise AddressOverlapError(
                        'Starting addresses are different')
                elif overlap == 'replace':
                    self.start_addr = other.start_addr

    def segments(self):
        """Return a list of ordered tuple objects, representing contiguous occupied data addresses.
        Each tuple has a length of two and follows the semantics of the range and xrange objects.
        The second entry of the tuple is always an integer greater than the first entry.
        """
        addresses = self.addresses()
        if not addresses:
            return []
        elif len(addresses) == 1:
            return([(addresses[0], addresses[0]+1)])
        adjacent_differences = [(b - a) for (a, b) in zip(addresses[:-1], addresses[1:])]
        breaks = [i for (i, x) in enumerate(adjacent_differences) if x > 1]
        endings = [addresses[b] for b in breaks]
        endings.append(addresses[-1])
        beginings = [addresses[b+1] for b in breaks]
        beginings.insert(0, addresses[0])
        return [(a, b+1) for (a, b) in zip(beginings, endings)]
#/IntelHex


def hex2boot(fin, fout, start=None, end=None, size=None, pad=None):
    """Hex-to-Boot convertor engine.
    @return     0   if all OK

    @param  fin     input hex file (filename or file-like object)
    @param  fout    output bin file (filename or file-like object)
    @param  start   start of address range (optional)
    @param  end     end of address range (inclusive; optional)
    @param  size    size of resulting file (in bytes) (optional)
    @param  pad     padding byte (optional)
    """
    try:
        h = intelhex(fin)
    except HexReaderError:
        e = sys.exc_info()[1]     # current exception
        txt = "ERROR: bad HEX file: %s" % str(e)
        print(txt)
        return 1

    # start, end, size
    if size != None and size != 0:
        if end == None:
            if start == None:
                start = h.minaddr()
            end = start + size - 1
        else:
            if (end+1) >= size:
                start = end + 1 - size
            else:
                start = 0

    try:
        if pad is not None:
            # using .padding attribute rather than pad argument to function call
            h.padding = pad
        h.tobinfile(fout, start, end)
    except IOError:
        e = sys.exc_info()[1]     # current exception
        txt = "ERROR: Could not write to file: %s: %s" % (fout, str(e))
        print(txt)
        return 1

    return 0

if __name__ == '__main__':

    usage = '''Hex2Boot convertor utility.
Usage:
    python hex2boot.py [options] INFILE [OUTFILE]

Arguments:
    INFILE      name of hex file for processing.
    OUTFILE     name of output file. If omitted then output
                will be writing to stdout.

Options:
    -h, --help              this help message.
    -v, --version           version info.
    -p, --pad=FF            pad byte for empty spaces (ascii hex value).
    -r, --range=START:END   specify address range for writing output
                            (ascii hex value).
                            Range can be in form 'START:' or ':END'.
    -l, --length=NNNN,
    -s, --size=NNNN         size of output (decimal value).
'''

    pad = None
    start = None
    end = None
    size = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvp:r:l:s:",
                                  ["help", "version", "pad=", "range=",
                                   "length=", "size="])

        for o, a in opts:
            if o in ("-h", "--help"):
                print(usage)
                sys.exit(0)
            elif o in ("-v", "--version"):
                print(VERSION)
                sys.exit(0)
            elif o in ("-p", "--pad"):
                try:
                    pad = int(a, 16) & 0x0FF
                except:
                    raise getopt.GetoptError('Bad pad value')
            elif o in ("-r", "--range"):
                try:
                    l = a.split(":")
                    if l[0] != '':
                        start = int(l[0], 16)
                    if l[1] != '':
                        end = int(l[1], 16)
                except:
                    raise getopt.GetoptError('Bad range value(s)')
            elif o in ("-l", "--lenght", "-s", "--size"):
                try:
                    size = int(a, 10)
                except:
                    raise getopt.GetoptError('Bad size value')

        if start != None and end != None and size != None:
            raise getopt.GetoptError('Cannot specify START:END and SIZE simultaneously')

        if not args:
            raise getopt.GetoptError('Hex file is not specified')

        if len(args) > 2:
            raise getopt.GetoptError('Too many arguments')

    except getopt.GetoptError:
        msg = sys.exc_info()[1]     # current exception
        txt = 'ERROR: '+str(msg)  # that's required to get not-so-dumb result from 2to3 tool
        print(txt)
        print(usage)
        sys.exit(2)

    fin = args[0]
    if not os.path.isfile(fin):
        txt = "ERROR: File not found: %s" % fin  # that's required to get not-so-dumb result from 2to3 tool
        print(txt)
        sys.exit(1)

    if len(args) == 2:
        fout = args[1]
    else:
        # write to stdout
        fout = get_binary_stdout()

    sys.exit(hex2boot(fin, fout, start, end, size, pad))
