describe RAPI::RemoteFile do
  include TempHelper

  subject { RAPI::RemoteFile }

  before do
    RAPI.connect unless RAPI.connected?
    RAPI.mkdir(tmp) unless RAPI.exist?(tmp)
  end

  after do
    RAPI.rm_rf(tmp)
  end

  self::READ   = %w{r rb r+b rt r+t}
  self::WRITE  = %w{w wb w+b wt w+t}
  self::APPEND = %w{a ab a+b at a+t}
  self::CREATE = self::WRITE + self::APPEND

  describe "#open" do
    context "when target file exists" do
      before do
        RAPI.connect unless RAPI.connected?

        fixtures = File.expand_path("../fixtures", __FILE__)
        alphabet = File.join(fixtures, "alphabet.txt")
        RAPI.mkdir(tmp) unless RAPI.exist?(tmp)
        RAPI.upload(alphabet, tmp("tempfile"))
      end

      self::READ.each do |mode|
        it "should read file when mode is #{mode}" do
          subject.open(tmp("tempfile"), mode) do |file|
            file.size.should == 26
            file.pos.should == 0
          end
        end
      end

      self::APPEND.each do |mode|
        it "should append file when mode is #{mode}" do
          subject.open(tmp("tempfile"), mode) do |file|
            file.size.should == 26
            file.pos.should == 26
          end
        end
      end

      self::WRITE.each do |mode|
        it "should truncate file when mode is #{mode}" do
          subject.open(tmp("tempfile"), mode) do |file|
            file.size.should == 0
            file.pos.should == 0
          end
        end
      end
    end

    context "when target file does not exist" do
      self::READ.each do |mode|
        it "should fail when mode is #{mode}" do
          lambda do
            subject.open(tmp("tempfile"), mode) { }
          end.should raise_error(RAPI::RAPIError)

          RAPI.exist?(tmp("tempfile")).should be_false
        end
      end

      self::CREATE.each do |mode|
        it "should create file when mode is #{mode}" do
          subject.open(tmp("tempfile"), mode) { }

          RAPI.exist?(tmp("tempfile")).should be_true
        end
      end
    end
  end
end
