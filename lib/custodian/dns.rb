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
require 'resolv'

module Custodian
  module DNS
    class << self
      def record_set(operation, name, ip, secret)
          {
            hosted_zone_id: Custodian.aws_zone_id,
            change_batch: {
              comment: "#{operation} A record for #{name}",
              changes: [
                {
                  action: operation,
                  resource_record_set: {
                    name: "#{name}.cloud.compute.estate",
                    type: "A",
                    ttl: 60,
                    weight: 0,
                    set_identifier: "#{secret}",
                    resource_records: [
                      {value: "#{ip}"}
                    ]
                  }
                }
              ]
            }
          }
      end
      
      def set(name, ip, secret)
        Custodian.route53_client.change_resource_record_sets(
          record_set('UPSERT', name, ip, secret)
        )
      end

      def clear(name, ip, secret)
        Custodian.route53_client.change_resource_record_sets(
          record_set('DELETE', name, ip, secret)
        )
      rescue Aws::Route53::Errors::InvalidChangeBatch
        STDERR.puts "Unable to DELETE: #{$!.message}"
        false
      end

      def resolve(name)
        fqdn = "#{name}.cloud.compute.estate"
        Resolv::DNS.open do |r|
          # check if we're resolving the wildcard (which is a CNAME)
          if r.getresources(fqdn, Resolv::DNS::Resource::IN::CNAME).empty?
            # we're not resolving the wildcard, so let's get the
            # existing A record.
            r.getresource(fqdn, Resolv::DNS::Resource::IN::A).address.to_s
          end
        end
      rescue Resolv::ResolvError
        nil
      end
      
      def exists?(name)
        !resolve(name).nil?
      end
      
      def await(name, expected_ip = nil)
        await(name,
              ->(addr) { !addr.nil? && (expected_ip.nil? || addr == expected_ip) },
              "Waiting for #{name} to have expected IP of #{expected_ip}")
      end

      def await_unresolvable(name)
        await(name,
              ->(addr) { addr.nil? },
              "Waiting for #{name} to lose A record")
      end

      def await(name, condition, message)
        loop do
          resolved_ip = resolve(name)
          STDERR.puts "Resolved #{name} to #{resolved_ip.nil? ? '<none>' : resolved_ip}"
          break if condition.call(resolved_ip)
          STDERR.puts message
          sleep 5
        end
      end
    end
  end
end
