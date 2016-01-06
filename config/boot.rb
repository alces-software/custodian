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
require 'bundler'
Bundler.setup

require 'pathname'
here = Pathname.new(__FILE__).realpath

$:.unshift File.expand_path("../../lib", here)
$:.unshift File.expand_path("../../config", here)

require 'custodian'
Custodian.root = File.expand_path("../..", here)
Custodian.public_ip = ENV['ALCES_PUBLIC_IP']
Custodian.aws_zone_id = ENV['ALCES_AWS_ZONE_ID']
Custodian.aws_access_key = ENV['ALCES_AWS_ACCESS_KEY']
Custodian.aws_secret_key = ENV['ALCES_AWS_SECRET_KEY']
Custodian.account_key_bucket = ENV['ALCES_ACCOUNT_KEY_BUCKET']
Custodian.account_key_object_key = ENV['ALCES_ACCOUNT_KEY_OBJECT_KEY']
Custodian.naming_secret = ENV['ALCES_NAMING_SECRET']
Custodian.dns_ttl = ENV['ALCES_DNS_TTL'] || 60
Custodian.dns_domain_name = ENV['ALCES_DNS_DOMAIN_NAME'] || 'cloud.compute.estate'

keyfile = File.expand_path("../account.pem", here)
if File.exists?(keyfile)
  Custodian.private_key = OpenSSL::PKey::RSA.new(File.read(keyfile))
else
  # attempt to retrieve from S3
  if Custodian.fetch_key || Custodian.generate_key
    File.write(keyfile, Custodian.private_key.to_pem)
  end
end

Dir[File.join(Custodian.root, 'lib', 'custodian', '*.rb')].each do |f|
  require f
end
