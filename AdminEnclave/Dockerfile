# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

from ubuntu:22.04

ENV app_user=duet

RUN groupadd -o -g 1000 -r ${app_user} && useradd -d /home/${app_user} -u 1000 -m -r -g ${app_user} ${app_user}

RUN apt-get update --fix-missing \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    wget \
    python3 \
    python3-pip \
    python-is-python3

# Python
RUN /usr/bin/python3 -m pip install --upgrade pip
ADD requirements.txt /tmp/
RUN /usr/bin/python3 -m pip install -r /tmp/requirements.txt

RUN apt-get clean

RUN mkdir -p /home/${app_user}/AdminEnclave
RUN mkdir -p /home/${app_user}/AdminEnclave/sealed
RUN mkdir -p /home/${app_user}/AdminEnclave/service_owner_pub_keys
RUN mkdir -p /home/${app_user}/tmp

ADD __init__.py /home/${app_user}/AdminEnclave/
ADD admin.py /home/${app_user}/AdminEnclave/
ADD azure_client.py /home/${app_user}/AdminEnclave/
ADD cvm.py /home/${app_user}/AdminEnclave/

RUN mkdir -p /home/${app_user}/AdminEnclave/utils
ADD utils/*.py /home/${app_user}/AdminEnclave/utils/

ADD azure_config.env /home/${app_user}/AdminEnclave/
ADD snp_cvm_commands.sh /home/${app_user}/AdminEnclave/
ADD tdx_cvm_commands.sh /home/${app_user}/AdminEnclave/

RUN rm -rf /home/${app_user}/.cache
RUN chown ${app_user}:${app_user} -R /home/${app_user}
USER ${app_user}

WORKDIR /

CMD ["python3", "-m", "home.duet.AdminEnclave.admin"]
