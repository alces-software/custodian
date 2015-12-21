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
      def record_set(operation, name, ip)
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
                    set_identifier: "${cw_NAMING_secret}",
                    resource_records: [
                      {value: "#{ip}"}
                    ]
                  }
                }
              ]
            }
          }
      end
      
      def set(name, ip)
        Custodian.route53_client.change_resource_record_sets(
          record_set('UPSERT', name, ip)
        )
      end

      def clear(name, ip)
        Custodian.route53_client.change_resource_record_sets(
          record_set('DELETE', name, ip)
        )
      rescue Aws::Route53::Errors::InvalidChangeBatch
        STDERR.puts "Unable to DELETE: #{$!.message}"
        true
      end

      def resolve(name)
        Resolv.getaddress("#{name}.cloud.compute.estate")
      rescue Resolv::ResolvError
        nil
      end
      
      def exists?(name)
        !resolve(name).nil?
      end
      
      def await(name, expected_ip = nil)
        loop do
          resolved_ip = resolve(name)
          if !resolved_ip.nil? && (expected_ip.nil? || resolved_ip == expected_ip)
            break
          end
          STDERR.puts 'waiting...'
          sleep 5
        end
      end
    end
  end
end
