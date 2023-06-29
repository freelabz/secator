from io import open
from os import path
import sys

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))
name = "secator"
description = "Security tools command runner"
version = "0.0.1"
release_status = "Development Status :: 3 - Alpha"
dependencies = [
    'bs4',
    'celery',
    'colorama',
    'cpe',
    'dotmap',
    'free-proxy',
    'furl',
    'jinja2',
    'humanize',
    'netifaces',
    'pygments',
    'python-dotenv',
    'pyyaml',
    'redis',
    'requests',
    'rich',
    'rich-click',
    'tabulate',
    'termcolor',
    'validators',
    'xmltodict'
]
extras = {
    'dev': ['coverage', 'flake8', 'watchdog'],
    'devops': ['asciinema-automation'],
    'google': ['google-api-python-client', 'google-auth', 'gspread']
}
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()
sys.dont_write_bytecode = True

setup(name=name,
      version=version,
      description=description,
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='FLZ Security',
      author_email='olivier.cervello@gmail.com',
      license='MIT',
      packages=find_packages(exclude=['contrib', 'docs']),
      classifiers=[
          release_status,
          'Intended Audience :: Developers',
          'Programming Language :: Python',
      ],
      keywords='recon framework vulnerability pentest automation',
      install_requires=dependencies,
      include_package_data=True,
      extras_require=extras,
      entry_points={
          'console_scripts': ['secator=secator.cli:cli'],
      },
      python_requires='>=3.8')
