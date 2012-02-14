require 'ffi'
require 'iconv'

module RAPI

  attr_accessor :copy_buffer_size

  class << self
    @connected = false
    @copy_buffer_size = 0x1000

    def connected?
      @connected
    end

    def connect(timeout_seconds = 1)
      self.disconnect if connected?

      init = Native::Rapi::RAPIINIT.new
      init[:cbSize] = Native::Rapi::RAPIINIT.size
      ret = Native::Rapi.CeRapiInitEx(init)
      handle_hresult! ret
      init_event = init[:heRapiInit]

      timeout = timeout_seconds * 4
      infinite_timeout = timeout < 0

      begin
        ret = Native::Kernel32.WaitForSingleObject(init_event, 250)

        if ret == Native::WAIT_FAILED || ret == Native::WAIT_ABANDONED
          Native::Kernel32.CloseHandle(init_event)
          Native::Rapi.CeRapiUninit
          raise RAPIException, "Failed to Initialize RAPI"
        end

        if !infinite_timeout
          if (timeout -= 1) < 0
            Native::Kernel32.CloseHandle(init_event)
            Native::Rapi.CeRapiUninit
            raise RAPIException, "Timeout waiting for device connection"
          end
        end
      end while ret != Native::WAIT_OBJECT_0

      @connected = true
      Native::Kernel32.CloseHandle(init_event)

      true
    end

    def disconnect
      if connected?
        Native::Rapi.CeRapiUninit
        @connected = false
      end

      true
    end

    def exist?(remote_file_name)
      check_connection()

      Native::Rapi::CeGetFileAttributes(Util.utf16le(remote_file_name)) != 0xFFFFFFFF
    end

    alias exists? exist?

    def download(remote_file_name, local_file_name, overwrite = false)
      check_connection()

      if !overwrite && File.exists?(local_file_name)
        raise RAPIException, "A local file with the given name already exists"
      end

      remote_file = Native::Rapi.CeCreateFile(Util.utf16le(remote_file_name), Native::GENERIC_READ, 0, 0, Native::OPEN_EXISTING, Native::FILE_ATTRIBUTE_NORMAL, 0)
      if remote_file == Native::INVALID_HANDLE
        raise RAPIException, "Could not open remote file"
      end

      File.open(local_file_name, "wb") do |f|
        buffer = FFI::MemoryPointer.new(1, @copy_buffer_size)
        bytes_read_ptr = FFI::MemoryPointer.new(:uint)

        while true
          ret = Native::Rapi.CeReadFile(remote_file, buffer, buffer.size, bytes_read_ptr, 0)

          bytes_read = bytes_read_ptr.get_int(0)

          if bytes_read != 0 && ret == 0
            buffer.free
            bytes_read_ptr.free
            Native::Rapi.CeCloseHandle(remote_file)
            raise RAPIException, "Failed to read device data"
          elsif bytes_read == 0
            break
          end

          f << buffer.get_bytes(0, bytes_read)
        end

        buffer.free
        bytes_read_ptr.free
        Native::Rapi.CeCloseHandle(remote_file)
      end

      true
    end

    def upload(local_file_name, remote_file_name, overwrite = false)
      check_connection()

      create = overwrite ? Native::CREATE_ALWAYS : Native::CREATE_NEW
      remote_file = Native::Rapi.CeCreateFile(Util.utf16le(remote_file_name), Native::GENERIC_WRITE, 0, 0, create, Native::FILE_ATTRIBUTE_NORMAL, 0)

      if remote_file == Native::INVALID_HANDLE
        raise RAPIException, "Could not create remote file"
      end

      if File.size(local_file_name) != 0
        File.open(local_file_name, "rb") do |f|
          while buffer = f.read(copy_buffer_size)
            if Native::Rapi.CeWriteFile(remote_file, buffer, buffer.size, nil, 0) == 0
              Native::Rapi.CeCloseHandle(remote_file)
              raise RAPIException, "Could not write to remote file"
            end
          end
        end
      end

      Native::Rapi.CeCloseHandle(remote_file)

      true
    end

    def copy(existing_file_name, new_file_name, overwrite = false)
      check_connection()

      if Native::Rapi.CeCopyFile(Util.utf16le(existing_file_name), Util.utf16le(new_file_name), overwrite ? 0 : 1) == 0
        raise RAPIException, "Cannot copy file"
      end

      true
    end

    def delete(file_name)
      check_connection()

      if Native::Rapi.CeDeleteFile(Util.utf16le(file_name)) == 0
        raise RAPIException, "Could not delete file"
      end

      true
    end

    def move(existing_file_name, new_file_name)
      check_connection()

      if Native::Rapi.CeMoveFile(Util.utf16le(existing_file_name), Util.utf16le(new_file_name)) == 0
        raise RAPIException, "Cannot move file"
      end

      true
    end

    def get_attributes(file_name)
      check_connection()

      ret = Native::Rapi.CeGetFileAttributes(Util.utf16le(file_name))
      if ret == 0xFFFFFFFF
        raise RAPIException, "Could not get file attributes"
      end

      FileAttributes.new(ret)
    end

    alias get_attrs get_attributes

    def set_attributes(file_name, attributes)
      check_connection()

      if Native::Rapi.CeSetFileAttributes(Util.utf16le(file_name), attributes.to_i) == 0
        raise RAPIExcpetion, "Cannot set device file attributes"
      end
    end

    alias set_attrs set_attributes

    def search(search_term)
      check_connection()

      file_infos = []

      ppFindDataArray = FFI::MemoryPointer.new(:pointer)
      count_ptr = FFI::MemoryPointer.new(:uint)
      success = Native::Rapi::CeFindAllFiles(Util.utf16le(search_term), 255, count_ptr, ppFindDataArray)
      if success
        count = count_ptr.get_uint(0)
        if count > 0
          array_ptr = FFI::Pointer.new(Native::Rapi::CE_FIND_DATA, ppFindDataArray.get_pointer(0))
          directory = Util.sanitize_path(search_term)

          (0...count).each do |n|
            info = FileInformation.new(directory, Native::Rapi::CE_FIND_DATA.new(array_ptr[n]))
            file_infos << info
          end

          Native::Rapi::CeRapiFreeBuffer(array_ptr)
        end
      end

      file_infos
    end

    alias glob search

    def exec(file_name, *args)
      check_connection()

      args = if args.empty?
               nil
             else
               args.join(' ')
             end

      pi = Native::Rapi::PROCESS_INFORMATION.new

      if Native::Rapi.CeCreateProcess(Util.utf16le(file_name), Util.utf16le(args), nil, nil, 0, 0, nil, nil, nil, pi) == 0
        errnum = Native::Rapi.CeGetLastError
        handle_hresult! errnum
      end

      ProcessInformation.new(pi)
    end

    def tmp
      check_connection()

      buffer = FFI::MemoryPointer.new(:uint16, Native::MAX_PATH + 1)
      temp_path = nil
      if Native::Rapi.CeGetTempPath(Native::MAX_PATH, buffer) != 0
        temp_path = Util.utf8(buffer.get_bytes(0, Native::MAX_PATH * 2))
      end

      temp_path
    end

    def open(path, *rest)
      check_connection()

      file = RemoteFile.new(path, *rest)
      if block_given?
        begin
          yield file
        ensure
          file.close
        end
      else
        file
      end
    end

    private

    def check_connection
      unless connected?
        raise RAPIException, "Cannot perform operation while disconnected"
      end
    end

    def handle_hresult!(hresult)
      if hresult != 0
        raise RAPIException, Util.format_msg(hresult)
      end
    end
  end

  class RemoteFile
    include File::Constants

    attr_reader :path
    attr_reader :pos
    alias tell pos

    def initialize(path, *rest)
      @path = path.freeze
      @pos = 0
      @mode, opt = splat_args(rest)

      @mode = parse_mode(@mode)
      append = @mode & APPEND != 0
      access_flags = mode_to_access(@mode)
      creation_flags = mode_to_creation(@mode)

      @remote_file = Native::Rapi.CeCreateFile(Util.utf16le(path), access_flags, 0, 0, creation_flags, Native::FILE_ATTRIBUTE_NORMAL, 0)

      if @remote_file == Native::INVALID_HANDLE
        raise RAPIException, "Could not create remote file"
      end

      self.pos = self.size if append
    end

    def stat
      RAPI.search(@path).first
    end

    def size
      # If I pass in a non-NULL uint* for the high DWORD,
      # the func always gives me 0 for both the low and high DWORDs...
      size = Native::Rapi.CeGetFileSize(@remote_file, nil)

      if size == Native::INVALID_FILE_SIZE
        raise RAPIException, "Could not get file size"
      end

      size
    end

    def write(obj)
      buffer = obj.to_s
      bytes_written_ptr = FFI::MemoryPointer.new(:uint)

      success = Native::Rapi.CeWriteFile(@remote_file, buffer, buffer.size, bytes_written_ptr, 0) != 0

      bytes_written = bytes_written_ptr.get_uint(0)
      @pos += bytes_written

      unless success
        raise RAPIException, "Could not write to remote file"
      end

      bytes_written
    end

    def <<(obj)
      write(obj)

      self
    end

    def read(*rest)
      length, buffer = rest
      buffer ||= ""
      buffer.clear

      if length.nil? || (length + self.pos) > self.size
        length = self.size - self.pos
      end

      if length == 0
        return nil if rest[0] && rest[0] > 0
        return ""
      end

      mem_buffer = FFI::MemoryPointer.new(:char, length)
      bytes_read_ptr = FFI::MemoryPointer.new(:uint)

      success = Native::Rapi.CeReadFile(@remote_file, mem_buffer, size, bytes_read_ptr, 0) != 0

      bytes_read = bytes_read_ptr.get_int(0)
      @pos += bytes_read

      unless success
        mem_buffer.free
        bytes_read_ptr.free
        raise RAPIException, "Failed to read device data"
      end

      buffer << mem_buffer.get_bytes(0, bytes_read)

      mem_buffer.free
      bytes_read_ptr.free

      buffer
    end

    def pos=(integer)
      seek(integer)
    end

    def seek(amount, whence=IO::SEEK_SET)
      case whence
      when IO::SEEK_SET
        new_pos = amount
        method = Native::FILE_BEGIN
      when IO::SEEK_CUR
        new_pos = @pos + amount
        method = Native::FILE_CURRENT
      when IO::SEEK_END
        new_pos = @pos + amount
        method = Native::FILE_END
      end

      Native::Rapi.CeSetFilePointer(@remote_file, amount, nil, method)
      @pos = new_pos
    end

    def truncate(integer)
      old_pos = self.pos
      self.pos = integer
      Native::Rapi.CeSetEndOfFile(@remote_file)
      self.pos = old_pos
    end

    def close
      Native::Rapi.CeCloseHandle(@remote_file)
      @remote_file = nil
    end

    def closed?
      @remote_file.nil?
    end

    private

    def splat_args(args)
      mode = "r"
      opt  = {}

      if args.size == 1
        if args[0].is_a?(String)
          mode = args[0]
        else
          opt  = args[0]
          mode = opt[:mode] if opt[:mode]
        end
      else
        mode = args[0]
        opt  = args[1]
      end

      [mode, opt]
    end

    def mode_to_access(mode)
      flags = 0

      if mode & RDWR != 0
        flags = Native::GENERIC_READ | Native::GENERIC_WRITE
      elsif mode & WRONLY != 0
        flags = Native::GENERIC_WRITE
      else
        flags = Native::GENERIC_READ
      end

      flags
    end

    def mode_to_creation(mode)
      flag = 0

      if mode & TRUNC != 0
        if mode & CREAT != 0
          flag = Native::CREATE_ALWAYS
        else
          flag = Native::TRUNCATE_EXISTING
        end
      elsif mode & CREAT != 0
        flag = Native::OPEN_ALWAYS
      else
        flag = Native::OPEN_EXISTING
      end

      flag
    end

    def parse_mode(mode)
      if mode.is_a?(String)
        pattern = /^(w|r|a)\+?(b|t)?$/

        unless pattern.match(mode)
          raise ArgumentError, "invalid access mode #{mode}"
        end

        mode_hash = {
          "r"  => RDONLY,
          "r+" => RDWR,
          "w"  => WRONLY | TRUNC | CREAT,
          "w+" => RDWR | TRUNC | CREAT,
          "a"  => WRONLY | APPEND | CREAT,
          "a+" => RDWR | APPEND | CREAT,
          "b"  => BINARY,
          "t"  => 0,
          ""   => 0
        }

        enum = mode_hash[mode.delete("b").delete("t")] |
               mode_hash[mode.delete("r").delete("w").delete("a").delete("+")]

        enum
      else
        mode
      end
    end
  end

  module Util
    def self.format_msg(errnum)
      msg_ptr = FFI::MemoryPointer.new(FFI::Pointer)
      format = Native::FORMAT_MESSAGE_ALLOCATE_BUFFER | Native::FORMAT_MESSAGE_FROM_SYSTEM | Native::FORMAT_MESSAGE_IGNORE_INSERTS
      len = Native::Kernel32.FormatMessageA(format, nil, errnum, 0, msg_ptr, 0, nil)
      if len == 0
        msg = "Error {hresult} (0x#{hresult.to_s(16).upcase})"
      else
        msg = msg_ptr.get_pointer(0).get_string(0).rstrip
      end
      Native::Kernel32.LocalFree(msg_ptr.get_pointer(0))
      msg_ptr.free

      msg
    end

    def self.sanitize_path(path)
      # Remove wildcards and such
      path = File.expand_path("/" + File.dirname(path)).gsub(%r{^([a-z]:|\\|/|\.)}i, '')

      # Make sure each part is properly cased
      clean_path = ""

      pieces = path.split(%r{/|\\}).select {|p| !p.empty?}

      pieces.each do |piece|
        search_term = clean_path + "/" + piece

        ppFindDataArray = FFI::MemoryPointer.new(:pointer)
        count_ptr = FFI::MemoryPointer.new(:uint)
        success = Native::Rapi::CeFindAllFiles(Util.utf16le(search_term), 255, count_ptr, ppFindDataArray) != 0
        if success
          count = count_ptr.get_uint(0)

          if count > 0
            array_ptr = FFI::Pointer.new(Native::Rapi::CE_FIND_DATA, ppFindDataArray.get_pointer(0))

            info = FileInformation.new("", Native::Rapi::CE_FIND_DATA.new(array_ptr[0]))
            clean_path << "/" + info.name

            Native::Rapi::CeRapiFreeBuffer(array_ptr)
          end
        else
          raise RAPIException, "Could not read file info"
        end
      end

      clean_path
    end

    if RUBY_VERSION =~ /^1\.9\.\d/
      def self.utf16le(str)
        return nil if str.nil?
        str.encode("UTF-16LE") + "\0\0".force_encoding("UTF-16LE")
      end

      def self.utf8(path)
        if index = path.index("\0\0")
          index += 1 if index.odd?
          path = path.slice(0, index)
        end

        path.force_encoding("UTF-16LE").encode("UTF-8")
      end
    else
      def self.utf16le(str)
        return nil if str.nil?
        Iconv.conv("UTF-16LE", "ASCII", str) + "\0\0"
      end

      def self.utf8(path)
        if index = path.index("\0\0")
          index += 1 if index.odd?
          path = path.slice(0, index)
        end

        Iconv.conv("ASCII", "UTF-16LE", path)
      end
    end
  end

  class ProcessInformation
    attr_reader :process_handle
    attr_reader :thread_handle
    attr_reader :process_id
    attr_reader :thread_id

    def initialize(process_information)
      @process_handle = process_information[:hProcess]
      @thread_handle  = process_information[:hThread]
      @process_id     = process_information[:dwProcessId]
      @thread_id      = process_information[:dwThreadId]
    end
  end

  class FileInformation
    attr_reader :attributes
    attr_reader :ctime
    attr_reader :atime
    attr_reader :mtime
    attr_reader :size
    attr_reader :name
    attr_reader :path

    def initialize(directory, ce_find_data)
      @attributes = FileAttributes.new(ce_find_data[:dwFileAttributes]).freeze
      @ctime      = ce_find_data[:ftCreationTime].freeze
      @atime      = ce_find_data[:ftLastAccessTime].freeze
      @mtime      = ce_find_data[:ftLastWriteTime].freeze
      @name       = Util.utf8(ce_find_data[:cFileName].to_ptr.get_bytes(0, Native::MAX_PATH * 2)).freeze
      @size       = ce_find_data[:nFileSizeHigh] << 32 &&
                    ce_find_data[:nFileSizeLow]

      @path =  File.join(directory, @name).freeze
    end

    def file?
      self.attributes.file?
    end

    def directory?
      self.attributes.directory?
    end

    def <=>(other_info)
      @mtime <=> other_info.mtime if other_info.respond_to?(:mtime)
    end

  end

  class Enum

    private

    def self.enum_attr(name, num)
      name = name.to_s

      define_method(name + "?") do
        @attrs & num != 0
      end

      define_method(name + "=") do |set|
        if set
          @attrs |= num
        else
          @attrs &= ~num
        end
      end
    end

    public

    def initialize(attrs = 0)
      @attrs = attrs.to_i
    end

    def to_i
      @attrs
    end
  end

  class FileAttributes < Enum
    enum_attr :readonly,       0x0001
    enum_attr :hidden,         0x0002
    enum_attr :system,         0x0004
    enum_attr :directory,      0x0010
    enum_attr :archive,        0x0020
    enum_attr :in_rom,         0x0040
    enum_attr :normal,         0x0080
    enum_attr :temporary,      0x0100
    enum_attr :sparse,         0x0200
    enum_attr :reparse_point,  0x0400
    enum_attr :compressed,     0x0800
    enum_attr :rom_module,     0x2000
  end

  class RAPIException < Exception
  end

  module Native

    # Winbase.h
    WAIT_ABANDONED = 0x00000080
    WAIT_FAILED    = 0xFFFFFFFF
    WAIT_TIMEOUT   = 0x00000102
    WAIT_OBJECT_0  = 0x00000000

    INVALID_FILE_SIZE = 0xFFFFFFFF

    MAX_PATH = 260

    FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
    FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
    FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

    GENERIC_READ      = 0x80000000
    GENERIC_WRITE     = 0x40000000

    FILE_SHARE_READ   = 0x00000001
    FILE_SHARE_WRITE  = 0x00000002

    CREATE_NEW        = 0x00000001
    CREATE_ALWAYS     = 0x00000002
    OPEN_EXISTING     = 0x00000003
    OPEN_ALWAYS       = 0x00000004
    TRUNCATE_EXISTING = 0x00000005

    INVALID_HANDLE = FFI::Pointer.new(-1)

    FILE_BEGIN   = 0x00
    FILE_CURRENT = 0x01
    FILE_END     = 0x02

    FILE_ATTRIBUTE_ARCHIVE       = 0x00000020;
    FILE_ATTRIBUTE_COMPRESSED    = 0x00000800;
    FILE_ATTRIBUTE_DIRECTORY     = 0x00000010;
    FILE_ATTRIBUTE_ENCRYPTED     = 0x00004000;
    FILE_ATTRIBUTE_HIDDEN        = 0x00000002;
    FILE_ATTRIBUTE_INROM         = 0x00000040;
    FILE_ATTRIBUTE_NORMAL        = 0x00000080;
    FILE_ATTRIBUTE_READONLY      = 0x00000001;
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    FILE_ATTRIBUTE_ROMMODULE     = 0x00002000;
    FILE_ATTRIBUTE_SPARSE_FILE   = 0x00000200;
    FILE_ATTRIBUTE_SYSTEM        = 0x00000004;
    FILE_ATTRIBUTE_TEMPORARY     = 0x00000100;

    FILE_FLAG_WRITE_THROUGH   = 0x80000000;
    FILE_FLAG_OVERLAPPED      = 0x40000000;
    FILE_FLAG_RANDOM_ACCESS   = 0x10000000;
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    FAF_ATTRIB_CHILDREN          = 0x01000
    FAF_ATTRIB_NO_HIDDEN         = 0x02000
    FAF_FOLDERS_ONLY             = 0x04000
    FAF_NO_HIDDEN_SYS_ROMMODULES = 0x08000
    FAF_GETTARGET                = 0x10000

    FAF_ATTRIBUTES      = 0x01
    FAF_CREATION_TIME   = 0x02
    FAF_LASTACCESS_TIME = 0x04
    FAF_LASTWRITE_TIME  = 0x08
    FAF_SIZE_HIGH       = 0x10
    FAF_SIZE_LOW        = 0x20
    FAF_OID             = 0x40
    FAF_NAME            = 0x80

    class FILETIME
      extend FFI::DataConverter
      native_type :uint64

      def self.from_native(val, ctx)
        Time.at((val * 1.0e-07) + Time.new(1601).to_f)
      end

      def self.to_native(val, ctx)
        ((val.to_f - Time.new(1601).to_f) / 1.0e-07).to_i
      end
    end

    module Rapi
      extend FFI::Library
      ffi_lib 'rapi.dll'
      ffi_convention :stdcall

      class RAPIINIT < FFI::Struct
        layout  :cbSize,     :int,
                :heRapiInit, :pointer,
                :hrRapiInit, :int
      end

      class CE_FIND_DATA < FFI::Struct
        layout  :dwFileAttributes,  :uint,                0,
                :ftCreationTime,    FILETIME,             4,
                :ftLastAccessTime,  FILETIME,            12,
                :ftLastWriteTime,   FILETIME,            20,
                :nFileSizeHigh,     :uint,               28,
                :nFileSizeLow,      :uint,               32,
                :dwOID,             :uint,               36,
                :cFileName,         [:uint16, MAX_PATH], 40
      end

      class PROCESS_INFORMATION < FFI::Struct
        layout  :hProcess,       :pointer,
                :hThread,        :pointer,
                :dwProcessId,    :uint,
                :dwThreadId,     :uint
      end

      attach_function :CeRapiFreeBuffer, [:pointer], :uint
      attach_function :CeRapiInitEx, [RAPIINIT.by_ref], :int
      attach_function :CeRapiUninit, [], :int
      attach_function :CeRapiGetError, [], :uint
      attach_function :CeCloseHandle, [:pointer], :int
      attach_function :CeWriteFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeReadFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeRapiFreeBuffer, [:pointer], :void
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeCreateFile, [:pointer, :uint, :int, :int, :int, :int, :int], :pointer
      attach_function :CeCopyFile, [:pointer, :pointer, :int], :uint
      attach_function :CeDeleteFile, [:pointer], :uint
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeSetFileAttributes, [:pointer, :uint], :uint
      attach_function :CeFindFirstFile, [:pointer, CE_FIND_DATA.by_ref], :pointer
      attach_function :CeFindNextFile, [:pointer, CE_FIND_DATA.by_ref], :int
      attach_function :CeFindAllFiles, [:pointer, :uint, :pointer, :pointer], :uint
      attach_function :CeFindClose, [:pointer], :uint
      attach_function :CeCreateProcess, [:pointer, :pointer, :pointer, :pointer, :int, :int, :pointer, :pointer, :pointer, PROCESS_INFORMATION.by_ref], :uint
      attach_function :CeGetLastError, [], :uint
      attach_function :CeGetTempPath, [:int, :pointer], :int
      attach_function :CeSetFilePointer, [:pointer, :int, :pointer, :uint], :uint
      attach_function :CeSetEndOfFile, [:pointer], :uint
      attach_function :CeGetFileSize, [:pointer, :pointer], :uint
    end

    module Kernel32
      extend FFI::Library
      ffi_lib 'kernel32'
      ffi_convention :stdcall

      @blocking = true
      attach_function :WaitForSingleObject, [:pointer, :uint], :uint
      attach_function :FormatMessageW, [:uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int
      attach_function :FormatMessageA, [:uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int
      attach_function :CloseHandle, [:pointer], :uint
      attach_function :LocalFree, [:pointer], :pointer
    end
  end
end
