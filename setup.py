# Copyright 2018 Pasi Niemi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
from setuptools import setup

setup(name='web-auth-ssh',
      version='0.6',
      description='Tools for authenticating to ssh via keys given out with a web service',
      url='http://github.com/NitorCreations/web-auth-ssh',
      download_url='https://github.com/NitorCreations/web-auth-ssh/tarball/0.6',
      author='Pasi Niemi',
      author_email='pasi.niemi@nitor.com',
      license='Apache 2.0',
      packages=['wa_ssh'],
      include_package_data=True,
      scripts=[ 'bin/wa-ssh' ],
      entry_points={
          'console_scripts': [
              'wa-keyserver=wa_ssh.keyserver:main',
              'wa-pubkeys=wa_ssh.cli:wa_pubkeys',
              'wa-privkey=wa_ssh.cli:wa_privkey',
              'wa-user-host=wa_ssh.cli:wa_user_host',
              'wa-ssh=wa_ssh.cli:wa_ssh'
          ],
      },
      setup_requires=[
          'pytest-runner'
      ],
      install_requires=[
          'pyaml',
          'argcomplete',
          'pycrypto',
          'nitor-vault'
      ],
      tests_require=[
          'pytest',
          'pytest-mock',
          'pytest-cov'
      ],
      zip_safe=False)
