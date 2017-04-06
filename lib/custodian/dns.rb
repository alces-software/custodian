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
require 'resolv'
require 'json'

module Custodian
  module DNS
    class << self
      def ping_record_set(name, meta, secret)
        domain_metadata = (JSON.parse(metadata("#{name}").gsub('\"','"')) rescue nil)
        if domain_metadata
          domain_metadata['mtime'] = Time.now.to_i
          domain_metadata['meta'] = meta if meta
          {
            hosted_zone_id: Custodian.aws_zone_id,
            change_batch: {
              comment: "UPSERT TXT record for #{name}",
              changes: [
                {
                  action: "UPSERT",
                  resource_record_set: {
                    name: "#{name}.#{Custodian.dns_domain_name}",
                    type: "TXT",
                    ttl: Custodian.dns_ttl,
                    weight: 0,
                    set_identifier: "#{secret}",
                    resource_records: [
                      {value: %("#{domain_metadata.to_json.gsub('"','\"')}")}
                    ]
                  }
                }
              ]
            }
          }
        end
      end

      def record_set(operation, name, ip, meta, secret)
          {
            hosted_zone_id: Custodian.aws_zone_id,
            change_batch: {
              comment: "#{operation} A record for #{name}",
              changes: [
                {
                  action: operation,
                  resource_record_set: {
                    name: "#{name}.#{Custodian.dns_domain_name}",
                    type: "A",
                    ttl: Custodian.dns_ttl,
                    weight: 0,
                    set_identifier: "#{secret}",
                    resource_records: [
                      {value: "#{ip}"}
                    ]
                  }
                }
              ].tap do |a|
                if operation == 'DELETE'
                  domain_metadata = metadata("#{name}")
                else
                  domain_metadata = {ctime: Time.now.to_i}.tap do |h|
                    h[:meta] = meta if meta
                  end.to_json
                end
                if domain_metadata
                  a << {
                    action: operation,
                    resource_record_set: {
                      name: "#{name}.#{Custodian.dns_domain_name}",
                      type: "TXT",
                      ttl: Custodian.dns_ttl,
                      weight: 0,
                      set_identifier: "#{secret}",
                      resource_records: [
                        {value: %("#{domain_metadata.gsub('"','\"')}")}
                      ]
                    }
                  }
                end
              end
            }
          }
      end

      def set(name, ip, meta, secret)
        STDERR.puts "Setting DNS records for #{name} -> #{ip} (#{secret})"
        Custodian.route53_client.change_resource_record_sets(
          record_set('UPSERT', name, ip, meta, secret)
        )
      end

      def ping(name, meta, secret)
        STDERR.puts "Updating DNS TXT record for ping #{name} -> (#{secret})"
        if rs = ping_record_set(name, meta, secret)
          Custodian.route53_client.change_resource_record_sets(rs)
          true
        else
          STDERR.puts "Not found: #{name}"
          false
        end
      rescue
        STDERR.puts "#{$!.class.name}: #{$!.message}"
        STDERR.puts $!.backtrace.join("\n")
        raise
      end

      def clear(name, ip, secret)
        STDERR.puts "Clearing DNS record #{name} -> #{ip} (#{secret})"
        Custodian.route53_client.change_resource_record_sets(
          record_set('DELETE', name, ip, secret)
        )
      rescue Aws::Route53::Errors::InvalidChangeBatch
        STDERR.puts "Unable to DELETE: #{$!.message}"
        false
      end

      def resolve(name)
        STDERR.puts "Resolving DNS record for #{name}"
        fqdn = "#{name}.#{Custodian.dns_domain_name}"
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

      def metadata(name)
        STDERR.puts "Resolving metadata DNS record for #{name}"
        fqdn = "#{name}.#{Custodian.dns_domain_name}"
        Resolv::DNS.open do |r|
          # check if we're resolving the wildcard (which is a CNAME)
          r.getresource(fqdn, Resolv::DNS::Resource::IN::TXT).data
        end
      rescue Resolv::ResolvError
        nil
      end
      
      def exists?(name)
        !resolve(name).nil?
      end
      
      def await_resolvable(name, expected_ip = nil)
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

      def each_record(&block)
        read_records.values.each(&block)
      end

      private
      def read_records(records = {}, opts = {})
        resp = Custodian.route53_client.list_resource_record_sets(
          opts.merge(hosted_zone_id: Custodian.aws_zone_id)
        )
        resp.resource_record_sets.each do |rs|
          rs.resource_records.each do |rr|
            record = records[rs.name] ||= {
              name: rs.name.chomp(".#{Custodian.dns_domain_name}."),
              secret: rs.set_identifier
            }
            if rs.type == 'TXT'
              record[:metadata] = JSON.parse(rr.value[1..-2].gsub('\"','"')) rescue {}
            elsif rs.type == 'A'
              record[:ip] = rr.value
            end
          end
        end
        if resp.is_truncated
          read_records(
            records,
            {
              start_record_name: resp.next_record_name,
              start_record_type: resp.next_record_type,
              start_record_identifier: resp.next_record_identifier
            }
          )
        end
        records
      end
    end
  end
end
