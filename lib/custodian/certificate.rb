#==============================================================================
# Copyright (C) 2015-2017 Stephen F Norledge & Alces Software Ltd.
#
# This file is part of Alces Custodian.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this software.  If not, see
# <http://www.gnu.org/licenses/>.
#
# This package is available under a dual licensing model whereby use of
# the package in projects that are licensed so as to be compatible with
# AGPL Version 3 may use the package under the terms of that
# license. However, if AGPL Version 3.0 terms are incompatible with your
# planned use of this package, alternative license terms are available
# from Alces Software Ltd - please direct inquiries about licensing to
# licensing@alces-software.com.
#
# For more information, please visit <http://www.alces-software.com/>.
#==============================================================================
require 'securerandom'

module Custodian
  class Certificate
    DEFAULT_SECRET = SecureRandom.hex
    
    attr_accessor :key, :cert, :chain, :fullchain
    
    def initialize(key:, cert:, chain:, fullchain:)
      self.key = key
      self.cert = cert
      self.chain = chain
      self.fullchain = fullchain
    end
    
    class << self
      def issue(names)
        fqdns = names.map {|n| "#{n}.#{Custodian.dns_domain_name}"}
        if names.all?{|n| authorize(n)}
          csr = Acme::Client::CertificateRequest.new(names: fqdns)
          certificate = Custodian.acme_client.new_certificate(csr)
          Certificate.new(key: certificate.request.private_key.to_pem,
                          cert: certificate.to_pem,
                          chain: certificate.chain_to_pem,
                          fullchain: certificate.fullchain_to_pem)
        end
      end

      def authorize(name)
        unless Custodian.public_ip.nil?
          DNS.set(name, Custodian.public_ip, nil, DEFAULT_SECRET)
          DNS.await_resolvable(name, Custodian.public_ip)
        end
        attempts = 0
        begin
          authorization = Custodian.acme_client.authorize(domain: "#{name}.#{Custodian.dns_domain_name}")
        rescue Acme::Client::Error
          if (attempts += 1) > 10
            raise
          else
            STDERR.puts "Failed to authorize (#{$!.message}); will retry (#{attempts}/10)"
            sleep 0.5
            retry
          end
        end
        challenge = authorization.http01
        Challenges.setup(challenge) do
          if challenge.request_verification
            while challenge.verify_status == 'pending' do
              sleep 1
            end
            status = challenge.verify_status
            STDERR.puts "Verification status: #{status}"
            status == 'valid'
          else
            STDERR.puts "Request for verification failed."
            false
          end
        end
      rescue Acme::Client::Error
        STDERR.puts $!.message
        STDERR.puts $!.backtrace.join("\n")
        false
      ensure
        unless Custodian.public_ip.nil?
          DNS.clear(name, Custodian.public_ip, DEFAULT_SECRET)
        end
      end

      def revoke(cert, name, ip, secret)
        Custodian.acme_client.revoke_certificate(cert)
        DNS.clear(name, ip, secret)
        DNS.await_unresolvable(name)
      end
    end
  end
end
