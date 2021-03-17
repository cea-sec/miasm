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

FROM debian:buster
LABEL maintainer="Camille Mougey <commial@gmail.com>"

# Download needed packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.cache

WORKDIR /opt/miasm

# Install Requirements
COPY requirements.txt /opt/miasm/requirements.txt
RUN pip3 install -r requirements.txt
COPY optional_requirements.txt /opt/miasm/optional_requirements.txt
RUN pip3 install -r optional_requirements.txt

# Install miasm
COPY README.md /opt/miasm/README.md
COPY setup.py /opt/miasm/setup.py
COPY miasm /opt/miasm/miasm
RUN pip3 install .

# Get everything else
COPY . /opt/miasm

# Set user
RUN useradd miasm && \
    chown -Rh miasm /opt/miasm
USER miasm

# Default cmd
WORKDIR /opt/miasm/test
CMD ["/bin/bash", "-c", "/usr/bin/python3 test_all.py -m"]
