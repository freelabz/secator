from io import open
from os import path
import sys

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))
name = "secsy"
description = "Sexy security tools command runner"
version = "0.0.1"
release_status = "Development Status :: 3 - Alpha"
dependencies = [
    'bs4',
    'celery',
    'cpe',
    'dotmap',
    'free-proxy',
    'furl',
    'gspread',
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
    'test': ['coverage', 'flake8']
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
      packages=find_packages(exclude=['contrib', 'docs', 'tests']),
      classifiers=[
          release_status,
          'Intended Audience :: Developers',
          'Programming Language :: Python',
      ],
      keywords='recon framework vulnerability pentest automation',
      install_requires=dependencies,
      extras_require=extras,
      entry_points={
          'console_scripts': ['secsy=secsy.cli:cli'],
      },
      python_requires='>=3.8')
