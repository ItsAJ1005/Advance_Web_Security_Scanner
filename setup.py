from setuptools import setup, find_packages

setup(
    name='advance-web-security-scanner',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'flask',
        'requests',
        'urllib3'
    ],
)
