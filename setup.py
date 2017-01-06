from setuptools import setup

the_version = open("VERSION").read().strip()
print("Packaging the version " + the_version)

s = setup(
    install_requires=[
        'wireless',
        'netifaces',
        'psutil'
    ],
    name='PyAccessPoint',
    version=the_version,
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
