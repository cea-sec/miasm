# This file is part of Miasm-Docker.
# Copyright 2019 Camille Mougey <commial@gmail.com>
#
# Miasm-Docker is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Miasm-Docker is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Miasm-Docker. If not, see <http://www.gnu.org/licenses/>.

FROM debian:stretch
MAINTAINER Camille Mougey <commial@gmail.com>

# Download needed packages
RUN apt-get -qq update && \
    apt-get -qqy install python python3 libpython-dev libpython3-dev python-pyparsing python3-pyparsing python-pip python3-pip && \
    apt-get -qqy install gcc g++ && \
    apt-get -qq clean

# Get miasm
ADD . /opt/miasm
RUN cd /opt/miasm && \
    pip install -r requirements.txt && \
    pip install -r optional_requirements.txt && \
    pip install . && \
    pip3 install -r requirements.txt && \
    pip3 install -r optional_requirements.txt && \
    pip3 install .

# Set user
RUN useradd miasm && \
    chown -Rh miasm /opt/miasm
USER miasm

# Default cmd
WORKDIR /opt/miasm/test
CMD ["/bin/bash", "-c", "for v in 2 3; do /usr/bin/python$v test_all.py -m; done"]
