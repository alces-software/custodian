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
require 'pathname'
here = Pathname.new(__FILE__).realpath
require File.expand_path('../config/boot', here)

Dir[File.join(Custodian.root, 'app', 'controllers', '*.rb')].each do |f|
  require f
end

require 'rack/utils'

#use Rack::CommonLogger, Custodian.logger
use Rack::ContentLength
use Rack::Head
run Custodian::App
