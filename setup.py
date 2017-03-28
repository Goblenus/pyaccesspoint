from setuptools import setup
import os

if os.path.exists('README.rst'):
    with open('README.rst') as readme_rst_file:
        long_description = readme_rst_file.read()
else:
    long_description = 'No description'

s = setup(
    install_requires=[
        'wireless',
        'netifaces',
        'psutil'
    ],
    name='PyAccessPoint',
    version='0.2.5',
    description='Package to manage wifi hotspot on linux',
    long_description=long_description,
    license='GNU GPLv3',
    author='Anton Bautkin',
    author_email='antonbautkin@gmail.com',
    url='https://github.com/Goblenus/pyaccesspoint',
    packages=['PyAccessPoint'],
    entry_points={
        'console_scripts': [
            'pyaccesspoint = PyAccessPoint.main:main',
        ],
    }
)
