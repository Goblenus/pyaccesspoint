from setuptools import setup

s = setup(
    install_requires=[
        'wireless',
        'netifaces',
        'psutil'
    ],
    name='PyAccessPoint',
    version='0.0.10',
    description='Package to manage wifi hotspot on linux',
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
