#!/usr/bin/env ruby
# frozen_string_literal: true

require 'auth/version'

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


    def initialize
      @otp_key = {}
      leaf = ENV['OTP'] || "#{ENV['HOME']}/.config/otp.yml"

      File.file?(leaf) ? (read leaf) : (create leaf)
    end

    def create_password
      Digest::SHA1.hexdigest(ask(MSG[:create]) { |io| io.echo = MSG[:syms].sample })
                  .chars
                  .first(32)
                  .join
    end

    def create(save_leaf)
      exit if File.exist? save_leaf

      # Create the cipher since it is a new file
      c = OpenSSL::Cipher.new('aes-256-cbc')

      # Load encryption Cipher
      c.key = create_password

      # Initialize an OTP key
      add
      save cipher: c, path: save_leaf
    end

    def add
      more = 'y'

      while more =~ /y/
        # Prompt user for OTP service and secret
        @otp_key.merge!({ HighLine.new.ask(MSG[:name]) => HighLine.new.ask(MSG[:secret]) })
        more = HighLine.new.ask(MSG[:more])
      end
    end

    def save(cipher:, path:)
      data = { iv: cipher.random_iv.to_s }

      @otp_key.each_with_index do |name, secret|
        # Encrypt the secret
        cipher.encrypt
        encrypted = cipher.update(secret)
        encrypted << cipher.final

        # Stage the data to be saved
        data.merge!({ name => encrypted })
      end

      # Save the OTP file
      File.write(path, data.to_yaml, mode: 'wb')
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
        next if [:@otp_key].include?(v)

        list.merge!({ instance_variable_get(v).issuer => instance_variable_get(v).at(Time.now.to_i + 20) })
      end
      puts list.map { |k, v| "#{k}: #{v}" }.sort
    end
    nil
  end
  nil
end; nil
