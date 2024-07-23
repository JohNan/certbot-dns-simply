from setuptools import setup, find_packages

setup(
    name='certbot-dns-simply',
    version='0.1.0',
    description='Simply.com DNS Authenticator plugin for Certbot',
    url='https://github.com/JohNan/certbot-dns-simply',
    author='JohNan',
    author_email='johan.nanzen@gmail.com',
    license='Apache License 2.0',
    packages=find_packages(),
    install_requires=[
        'certbot',
        'requests',
        'requests-mock',
    ],
    entry_points={
        'certbot.plugins': [
            'dns-simply = certbot_dns_simply.dns_simply:Authenticator',
        ],
    },
    test_suite="certbot_dns_simply",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
