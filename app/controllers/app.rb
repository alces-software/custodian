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
require 'sinatra/base'
require 'json'

module Custodian
  class App < Sinatra::Base
    before do
      request.body.rewind
      body = request.body.read
      if body.length > 0
        @params = JSON.parse(body)
      end
    end
    
    get '/' do
      'OK'
    end

    post '/create' do
      name = @params['name']
      alts = @params['alts'] || []
      ip = @params['ip']
      secret = @params['secret']
      k = @params['k']
      s = @params['s']
      if Custodian.verified?(name, k, s)
        resolved_ip = Custodian::DNS.resolve(name)
        if !resolved_ip.nil?
          if Custodian::DNS.clear(name, resolved_ip, secret)
            Custodian::DNS.await_unresolvable(name)
          else
            STDERR.puts "Unable to clear existing IP (#{resolved_ip}) for #{name}"
            status 403
            return
          end
        end

        cert_data = Custodian::Certificate.issue(name, alts)
        Custodian::DNS.set(name, ip, secret)
        {
          cert: cert_data.cert,
          key: cert_data.key,
          fullchain: cert_data.fullchain
        }.to_json
      else
        status 403
      end
    end

    get '/.well-known/acme-challenge/:token' do
      if content = Challenges.challenge_files[".well-known/acme-challenge/#{params[:token]}"]
        content
      else
        status 404
      end
    end
  end
end
