from setuptools import setup
import os

if os.path.exists('README.md'):
    try:
        import pypandoc
        long_description = pypandoc.convert('README.md', 'rst')
    except(IOError, ImportError):
        long_description = open('README.md').read()
else:
    long_description = ''

s = setup(
    install_requires=[
        'wireless',
        'netifaces',
        'psutil'
    ],
    name='PyAccessPoint',
    version='0.0.6',
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
