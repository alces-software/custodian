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
require 'openssl'
require 'acme-client'
require 'acme/client'
require 'aws-sdk'
require 'digest'

module Custodian
  ENDPOINT = if ENV['ALCES_LETSENCRYPT_ENV'] == 'staging'
               'https://acme-staging.api.letsencrypt.org/'
             else
               'https://acme-v01.api.letsencrypt.org/'
             end
  DAYS_90 = 90 * 24 * 60 * 60
  DAYS_3 = 3 * 24 * 60 * 60

  Aws.config[:region] = 'us-east-1'

  class << self
    attr_accessor :root, :public_ip, :private_key,
                  :aws_access_key, :aws_secret_key, :aws_zone_id,
                  :account_key_bucket, :account_key_object_key,
                  :naming_secret, :dns_ttl, :dns_domain_name

    def acme_client
      @acme_client ||= Acme::Client.new(private_key: private_key, endpoint: ENDPOINT)
    end

    def s3_client
      @s3_client ||= Aws::S3::Client.new(
        access_key_id: aws_access_key,
        secret_access_key: aws_secret_key,
        region: 'eu-west-1'
      )
    end
    
    def route53_client
      @route53_client ||= Aws::Route53::Client.new(
        access_key_id: aws_access_key,
        secret_access_key: aws_secret_key
      )
    end
    
    def generate_key
      self.private_key = OpenSSL::PKey::RSA.new(2048)
      registration = acme_client.register(contact: 'mailto:certmaster@alces-software.com')
      registration.agree_terms
    end

    def fetch_key
      self.private_key = OpenSSL::PKey::RSA.new(
        s3_client.get_object(bucket: account_key_bucket,
                             key: account_key_object_key)
        .body.read)
    rescue Aws::S3::Errors::ServiceError
      nil
    end

    def verified?(name, k, s)
      k == Digest::MD5.hexdigest("#{name}:#{s}:#{naming_secret}")
    end

    def reap
      candidates = []
      # iterate over existing records, mark any that haven't been
      # updated for more than 3 days or have existed for more than 90 days.
      DNS.each_record do |r|
        if r[:metadata]
          if r[:metadata].key?('mtime')
            mtime = Time.at(r[:metadata]['mtime'].to_i)
            candidates << r if Time.now - mtime >= DAYS_3
          elsif r[:metadata].key?('ctime')
            ctime = Time.at(r[:metadata]['ctime'].to_i)
            candidates << r if Time.now - ctime >= DAYS_90
          end
        end
      end

      [].tap do |reaped|
        candidates.each do |r|
          reaped << r[:name] if DNS.clear(r[:name], r[:ip], r[:secret])
        end
      end
    end
  end
end
