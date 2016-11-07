#==============================================================================
# Copyright (C) 2015 Stephen F Norledge & Alces Software Ltd.
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
module Custodian
  class Certificate
    attr_accessor :key, :cert, :chain, :fullchain
    
    def initialize(key:, cert:, chain:, fullchain:)
      self.key = key
      self.cert = cert
      self.chain = chain
      self.fullchain = fullchain
    end
    
    class << self
      def issue(name, alts)
        unless Custodian.public_ip.nil?
          DNS.set(name, Custodian.public_ip)
          DNS.await(name, Custodian.public_ip)
        end
        
        if authorize(name)
          csr = Acme::Client::CertificateRequest.new(names: ["#{name}.#{Custodian.dns_domain_name}"].concat(alts))
          certificate = Custodian.acme_client.new_certificate(csr)
          Certificate.new(key: certificate.request.private_key.to_pem,
                          cert: certificate.to_pem,
                          chain: certificate.chain_to_pem,
                          fullchain: certificate.fullchain_to_pem)
        else
          unless Custodian.public_ip.nil?
            DNS.clear(name, Custodian.public_ip)
          end
        end
      end

      def authorize(name)
        authorization = Custodian.acme_client.authorize(domain: "#{name}.#{Custodian.dns_domain_name}")
        challenge = authorization.http01
        Challenges.setup(challenge) do
          if challenge.request_verification
            while challenge.verify_status == 'pending' do
              sleep 1
            end
            challenge.verify_status == 'valid'
          else
            false
          end
        end
      end
    end
  end
end
