#!/usr/bin/env ruby
#

require 'sqlite3'
require 'openssl'
require 'uri'
require 'pry'


module ChromeStorage
  class << self

    @@login_db_path = File.expand_path "~/Library/Application\ Support/Google/Chrome/Default/Login\ Data"
    @@cookie_db_path = File.expand_path "~/Library/Application Support/Google/Chrome/Default/Cookies"
    @@pass = nil
    def chrome_pass_in_keychain
      return @@pass if @@pass
      @@pass = ` security find-generic-password -ws "Chrome Safe Storage"`.strip
    end
    def decrypt(encrypted_value, pass )
      iter = 1003
      key_len = 16
      salt = "saltysalt"
      iv = " " * 16

      return if encrypted_value.size < 3

      key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass, salt, iter, key_len)

      cipher = OpenSSL::Cipher::AES.new(128,:CBC)
      cipher.decrypt
      cipher.iv = iv
      cipher.key = key

      data = encrypted_value
      data = data[3,data.size]

      return cipher.update(data) + cipher.final
    end
    def login_data_to_keychain(*args)
      data = dump_login_data(*args)
      data.each{|e|
         unless e[:username_value] && e[:password_value] then
            puts "skipping #{[:origin_url]}"
            next
         end

        u = URI.parse(e[:origin_url])
        cmd = %|security add-internet-password
          -a '#{e[:username_value]}'
          -d #{u.host}
          -p #{u.path}
          -r http
          -s #{u.host}
          -w '#{e[:password_value]}'
          -U
        |.lines.map(&:strip).join(" ")

        puts u.host

        `#{cmd}`
      }

    end

    def dump_login_data(search =nil )
      db = SQLite3::Database.new  @@login_db_path , :readonly => 1
      # binding.pry
      ## TODO ChromeがDBロックするので、TMPにコピーして処理する必要がある。
      db.results_as_hash = true

      sql = "select  origin_url , username_value , password_value from logins"
      ret = []

      begin
        if search then
          search = "%"+search+"%"
          sql += " where origin_url like :url"
          ret = db.execute(sql , {url:search})
        else
          ret = db.execute(sql)
        end
      rescue  SQLite3::BusyException => ex
          puts "chrome を終了しましょう"
          puts "Chrome 起動中は SQLite3がロックされてて、READ出来ません。"
          exit(1)
      end


      ret.map   do |e|
        v = e["password_value"]
        v = self.decrypt(v,  self.chrome_pass_in_keychain )
        e["password_value"] = v

        e = {
          origin_url: e["origin_url"],
          username_value: e["username_value"],
          password_value: e["password_value"],
        }
      end
    end

    def dump_cookie_data(search =nil )
      db = SQLite3::Database.new  @@cookie_db_path
      db.results_as_hash = true

      sql = "select host_key, path, name, value, encrypted_value, secure, httponly from cookies"
      ret = []

      if search then
        search = "%"+search+"%"
        sql += " where host_key like :url"
        ret = db.execute(sql , {url:search})
      else
        ret = db.execute(sql)
      end

      cookie_jar ={}
      ret.map   do |e|
        v = e["encrypted_value"]
        v = self.decrypt(v,  self.chrome_pass_in_keychain )
        e["decrypted_value"] = v

        cookie  = {
          path: e["path"],
          name: e["name"],
          value: e["decrypted_value"],
          secure: e["secure"],
          httponly: e["httponly"],
        }

        cookie_jar[ e["host_key"] ]  = []  unless  cookie_jar[ e["host_key"] ]
        cookie_jar[ e["host_key"] ] << cookie
      end
      cookie_jar
    end


  end
end
