module RAPI
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

      @handle = Native::Rapi.CeCreateFile(Util.utf16le(path), access_flags, 0, 0, creation_flags, Native::FILE_ATTRIBUTE_NORMAL, 0)

      unless @handle.valid?
        Util.handle_hresult! Util.error, "Could not create remote file."
      end

      self.pos = self.size if append
    end

    def stat
      RAPI.search(@path).first
    end

    def size
      # If I pass in a non-NULL uint* for the high DWORD,
      # the func always gives me 0 for both the low and high DWORDs...
      size = Native::Rapi.CeGetFileSize(@handle, nil)

      if size == Native::INVALID_FILE_SIZE
        Util.handle_hresult! Util.error, "Could not get file size."
      end

      size
    end

    def write(obj)
      buffer = obj.to_s
      bytes_written_ptr = FFI::MemoryPointer.new(:uint)

      success = Native::Rapi.CeWriteFile(@handle, buffer, buffer.size, bytes_written_ptr, 0) != 0

      bytes_written = bytes_written_ptr.get_uint(0)
      @pos += bytes_written

      unless success
        Util.handle_hresult! Util.error, "Could not write to remote file."
      end

      bytes_written

    ensure
      bytes_written_ptr.free if bytes_written_ptr
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
        return buffer
      end

      mem_buffer = FFI::MemoryPointer.new(:char, length)
      bytes_read_ptr = FFI::MemoryPointer.new(:uint)

      success = Native::Rapi.CeReadFile(@handle, mem_buffer, size, bytes_read_ptr, 0) != 0

      bytes_read = bytes_read_ptr.get_int(0)
      @pos += bytes_read

      unless success
        mem_buffer.free
        bytes_read_ptr.free
        Util.handle_hresult! Util.error, "Failed to read device data."
      end

      buffer << mem_buffer.get_bytes(0, bytes_read)


      buffer

    ensure
      mem_buffer.free if mem_buffer
      bytes_read_ptr.free if bytes_read_ptr
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

      success = Native::Rapi.CeSetFilePointer(@handle, amount, nil, method) != 0xFFFFFFFF

      unless success
        Util.handle_hresult! Util.error, "Failed to move file pointer."
      end

      @pos = new_pos
    end

    def truncate(integer)
      old_pos = self.pos
      self.pos = integer

      success = Native::Rapi.CeSetEndOfFile(@handle) != 0

      unless success
        Util.handle_hresult! Util.error, "Failed to truncate file."
      end

    ensure
      self.pos = old_pos
    end

    def close
      @handle.close
      @handle = nil
    end

    def closed?
      @handle.nil?
    end

    private

    def splat_args(args)
      mode = "r"
      opt  = {}

      if args.size == 1
        if args[0].is_a?(String)
          mode = args[0]
        else
          mode = opt[:mode] if opt[:mode]
          opt  = args[0]
        end
      else
        mode = args[0]
        opt  = args[1]
      end

      [mode, opt || {}]
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
end
