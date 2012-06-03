#!/usr/bin/env python
from setuptools import setup

setup(name='opensvp',
      version='0.2',
      description='Application layer gateway testing tool',
      author='Eric Leblond',
      author_email='eric@regit.org',
      url='https://home.regit.org/software/opensvp/',
      scripts=['opensvp'],
      packages=['opensvp'],
      package_dir={'opensvp':'lib/'},
      provides=['opensvp'],
      requires=['argparse', 'scapy', 'ftplib'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: System :: Networking :: Firewalls',
          ],
      )
