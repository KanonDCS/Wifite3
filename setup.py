from distutils.core import setup
from wifite.config import Configuration

setup(
    name='wifite',
    version=Configuration.version,
    author='KanonDCS',
    author_email='kanondcs@proton.me',
    url='https://github.com/KanonDCS/wifite3',
    packages=[
        'wifite',
        'wifite/attack',
        'wifite/model',
        'wifite/tools',
        'wifite/util',
    ],
    data_files=[
        ('share/dict', ['wordlist-top4800-probable.txt'])
    ],
    install_requires=[
        'scapy',
        'tqdm',
        'colorama'
    ],
    entry_points={
        'console_scripts': [
            'wifite = wifite.__main__:entry_point'
        ]
    },
    license='GNU GPLv2',
    scripts=['bin/wifite'],
    description='Wifite 3: High-Performance Wireless Network Auditor',
    long_description='''Wifite 3: High-Performance Wireless Network Auditor for Linux.
    Modernized and maintained by KanonDCS.

    Cracks WEP, WPA, WPA3, and WPS encrypted networks.
    Supports high-speed batch RSN parsing, safe anti-forensic shredding, and WPA3/SAE scanning.

    Depends on Aircrack-ng Suite, Tshark, and Scapy.''',
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Topic :: Security"
    ]
)
