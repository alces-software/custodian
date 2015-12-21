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
require 'openssl'
require 'acme-client'
require 'acme/client'
require 'aws-sdk'

module Custodian
  ENDPOINT = 'https://acme-v01.api.letsencrypt.org/'
  Aws.config[:region] = 'us-east-1'

  class << self
    attr_accessor :root, :public_ip, :private_key,
                  :aws_access_key, :aws_secret_key, :aws_zone_id

    def acme_client
      @acme_client ||= Acme::Client.new(private_key: private_key, endpoint: ENDPOINT)
    end

    def route53_client
      @route53_client ||= Aws::Route53::Client.new(
        access_key_id: aws_access_key,
        secret_access_key: aws_secret_key
      )
    end
    
    def generate_key
      self.private_key = OpenSSL::PKey::RSA.new(2048)
      registration = acme_client.register(contact: 'mailto:mark.titorenko@alces-software.com')
      registration.agree_terms
    end
  end
end
