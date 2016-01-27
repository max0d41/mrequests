from setuptools import setup

setup(
    name='mrequests',
    version='1.0.3',
    url='https://github.com/max0d41/mrequests',
    description='Extended python requests to make more browser-like HTTP requests',
    packages=[
        'mrequests',
    ],
    install_requires=[
        'requests',
        'beautifulsoup4'
    ],
    zip_safe=False
)
