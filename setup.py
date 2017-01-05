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
    # description='Small daemon to create a wifi hotspot on linux',
    # license='MIT',
    # author='Prahlad Yeri',
    # author_email='prahladyeri@yahoo.com',
    # url='https://github.com/prahladyeri/hotspotd',
    # py_modules=['hotspotd','cli'],

    packages=['PyAccessPoint'],

    # out of date
    # package_data={'hotspotd': ['run.dat']},

    # scripts=['PyAccessPointmain.py', 'pyaccesspoint.py'],

    entry_points={
        'console_scripts': [
            'pyaccesspoint = PyAccessPoint.main:main',
        ],
    }
)
