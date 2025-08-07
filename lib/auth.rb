#!/usr/bin/env ruby
# frozen_string_literal: true

# require 'auth/version'

# Encrypt-store OTP keys and access them quickly when you need them
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
      more: 'Would you like to add another OTP key? ',
      name: 'What service do you login to with this OTP? (amazon, google)',
      secret: 'Paste / Carefully-type the OTP secret string:',
      syms: ['!', '@', '#', '$', '%', '&', '*', '+', '=', '-']
    }.freeze

    PTH = {
      OTP: ENV['OTP'],
      XDG_CONFIG_HOME: "#{ENV['XDG_CONFIG_HOME']}/auth.otp",
      HOME: "#{ENV['HOME']}/.config/auth.otp"
    }.freeze

    def initialize
      @otp_key = Hash.new

      File.file?(leaf) ? read : create
    end

    def self.add
      more = 'y'

      while more =~ /y/
        # Prompt user for OTP service and secret
        @otp_key.merge!({ HighLine.new.ask(MSG[:name]) => HighLine.new.ask(MSG[:secret]) })

        more = HighLine.new.ask(MSG[:more])
      end
    end

    def self.create(save_leaf: determine_config)
      exit if File.exist? save_leaf

      add # Add a key

      # Initialize an OTP key
      save path: save_leaf
    end

    def self.create_password
      Digest::SHA1.hexdigest(ask(MSG[:create]) { |io| io.echo = MSG[:syms].sample })
                  .chars
                  .first(32)
                  .join
    end

    def self.determine_config
      %w[OTP XDG_CONFIG_HOME HOME].each do |config|
        next if ENV[config].nil?

        return PTH[config.to_sym]
      end
    end

    def self.read(leaf: determine_config)
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

      data.each_key do |v|
        next if [:iv].include?(v)

        list.merge!({ instance_variable_get("@#{v}").issuer => instance_variable_get("@#{v}").at(Time.now.to_i) })
      end
      puts list.map { |k, v| "#{k}: #{v}" }.sort
    end

    def self.save(path: determine_config)
      throw "Cowardly refusing to overwrite #{path}" if File.file?(path)
      # Create the cipher since it is a new file
      cipher = OpenSSL::Cipher.new('aes-256-cbc')

      data = { iv: cipher.random_iv.to_s }
      throw 'No Data' unless @otp_key.keys.count.positive?

      puts "Keys: #{@otp_key.keys}"
      @otp_key.each_key do |name|
        next if name == :iv

        # Encrypt the secret
        cipher.encrypt

        # Load encryption Cipher
        cipher.key = create_password
        cipher.iv  = data[:iv]

        encrypted = cipher.update(@otp_key[name])
        encrypted << cipher.final

        # Stage the data to be saved
        data.merge!({ name => encrypted })
      end

      # Save the OTP file
      File.write(path, data.to_yaml, mode: 'wb')
    end
  end
end
