require 'auth/version'

module Auth
  # Create or read OTP keys
  class OTP
    require 'digest/sha1'
    require 'highline/import'
    require 'openssl'
    require 'rotp'
    require 'yaml'

    MSG = {
      create: 'Create a password to protect OTP keys:',
      name: 'What service do you login to with this OTP? (amazon, google)',
      secret: 'Paste / Carefully-type the OTP secret string:',
      syms: ['!', '@', '#', '$', '%', '&', '*', '+', '=', '-']
    }.freeze

    def initialize
      leaf = ENV['OTP'] || "#{ENV['HOME']}/.config/otp.yml"

      File.file?(leaf) ? (read leaf) : (create leaf)
    end

    def create(save_leaf)
      exit if File.exist? save_leaf

      # Create the cipher since it is a new file
      c = OpenSSL::Cipher.new('aes-256-cbc')
      c.encrypt

      # Stage Key-components
      k = Digest::SHA1.hexdigest(
        ask(MSG[:create]) { |io| io.echo = MSG[:syms].sample }
      ).chars.first(32).join
      iv = c.random_iv

      # Load encryption Cipher
      c.key = k
      c.iv = iv

      # Initialize an OTP key
      add cipher: c, path: save_leaf, civ: iv
    end

    def add(cipher:, path:, civ:)
      # Prompt user for OTP service and secret
      otp_label  = HighLine.new.ask(MSG[:name])
      otp_secret = HighLine.new.ask(MSG[:secret])

      # Encrypt the secret (and it's label)
      enc =  cipher.update(otp_secret)
      enc << cipher.final

      # Stage the data to be saved
      data = {
        iv: civ.to_s,
        "#{otp_label}": enc
      }.to_yaml

      # Save the OTP file
      File.write(path, data, mode: 'wb')
    end

    def delete(otpe); end

    def destroy(otpc); end

    def read(leaf)
      data = YAML.load_file leaf
      list = {}
      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.decrypt
      cipher.iv = data[:iv]
      cipher.key = Digest::SHA1.hexdigest(
        ask('Encryption Passphrase: ') { |io| io.echo = MSG[:syms].sample }
      ).chars.first(32).join

      data.each do |h, k|
        next if h == :iv

        dec = cipher.update(k)
        dec << cipher.final
        instance_variable_set("@#{h}", ROTP::TOTP.new(dec.to_s, issuer: h.to_s))
      end

      instance_variables.each do |v|
        list.merge!({ instance_variable_get(v).issuer => instance_variable_get(v).now })
      end
      puts list.map { |k, v| "#{k}: #{v}" }.sort
    end
  end
end

Auth::OTP.new
